/**
 * Netlify Function : Proxy sécurisé pour le webhook des avis
 * 
 * Variable d'environnement à configurer dans Netlify :
 *   WEBHOOK_AVIS = https://discord.com/api/webhooks/...
 */

const ALLOWED_ORIGIN = 'https://devcenter.vyral-studio.fr';

const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 5 * 60 * 1000; // 5 minutes
const RATE_LIMIT_MAX = 2; // max 2 avis par 5min par IP (anti-spam)

function isRateLimited(ip) {
    const now = Date.now();
    const entry = rateLimitMap.get(ip) || { count: 0, start: now };

    if (now - entry.start > RATE_LIMIT_WINDOW_MS) {
        rateLimitMap.set(ip, { count: 1, start: now });
        return false;
    }

    if (entry.count >= RATE_LIMIT_MAX) return true;

    entry.count++;
    rateLimitMap.set(ip, entry);
    return false;
}

exports.handler = async (event) => {
    // ── CORS ─────────────────────────────────────────────────────────────
    const origin = event.headers['origin'] || '';
    if (origin !== ALLOWED_ORIGIN) {
        return { statusCode: 403, body: 'Forbidden' };
    }

    if (event.httpMethod !== 'POST') {
        return { statusCode: 405, body: 'Method Not Allowed' };
    }

    // ── Rate limiting (plus strict pour les avis) ─────────────────────────
    const ip = event.headers['x-forwarded-for']?.split(',')[0] || 'unknown';
    if (isRateLimited(ip)) {
        return {
            statusCode: 429,
            body: JSON.stringify({ error: 'Trop d\'avis envoyés. Attendez quelques minutes.' }),
            headers: { 'Content-Type': 'application/json' }
        };
    }

    let payload;
    try {
        payload = JSON.parse(event.body);
    } catch {
        return { statusCode: 400, body: 'Invalid JSON' };
    }

    // ── Validation stricte du contenu de l'avis ──────────────────────────
    const { username, userId, rating, comment, avatarUrl } = payload;

    if (!username || !userId || !rating || !comment) {
        return { statusCode: 400, body: 'Missing fields' };
    }

    // Valider la note (1-5 seulement)
    const safeRating = parseInt(rating);
    if (isNaN(safeRating) || safeRating < 1 || safeRating > 5) {
        return { statusCode: 400, body: 'Invalid rating' };
    }

    // Valider la longueur du commentaire
    const safeComment = String(comment).slice(0, 500);
    if (safeComment.trim().length < 5) {
        return { statusCode: 400, body: 'Comment too short' };
    }

    // Valider l'ID Discord (format numérique uniquement)
    if (!/^\d{15,20}$/.test(String(userId))) {
        return { statusCode: 400, body: 'Invalid user ID' };
    }

    const webhookUrl = process.env.WEBHOOK_AVIS;
    if (!webhookUrl) {
        return { statusCode: 500, body: 'Webhook not configured' };
    }

    const safePayload = {
        content: '⭐ **Nouvel avis reçu !**',
        embeds: [{
            title: '💬 Avis Client',
            color: 16777215,
            thumbnail: avatarUrl ? { url: String(avatarUrl).slice(0, 512) } : undefined,
            fields: [
                { name: 'Utilisateur', value: String(username).slice(0, 100), inline: true },
                { name: 'ID', value: String(userId).slice(0, 20), inline: true },
                { name: 'Note', value: '⭐'.repeat(safeRating), inline: false },
                { name: 'Commentaire', value: safeComment, inline: false }
            ],
            timestamp: new Date().toISOString()
        }]
    };

    try {
        const response = await fetch(webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(safePayload)
        });

        if (!response.ok) {
            return { statusCode: 502, body: 'Discord webhook failed' };
        }

        return {
            statusCode: 200,
            body: JSON.stringify({ success: true }),
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': ALLOWED_ORIGIN
            }
        };
    } catch {
        return { statusCode: 502, body: 'Network error' };
    }
};
