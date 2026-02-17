/**
 * Netlify Function : Proxy sécurisé pour le webhook de connexion
 * 
 * Le webhook Discord reste côté serveur dans les variables d'environnement Netlify.
 * Le client appelle /.netlify/functions/webhook-connexion
 * Cette fonction valide les données puis forwarde à Discord.
 * 
 * Variable d'environnement à configurer dans Netlify :
 *   WEBHOOK_CONNEXIONS = https://discord.com/api/webhooks/...
 */

const ALLOWED_ORIGIN = 'https://devcenter.vyral-studio.fr';

// Rate limiting en mémoire (se réinitialise au redémarrage de la fonction)
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX = 5; // max 5 appels par minute par IP

function isRateLimited(ip) {
    const now = Date.now();
    const entry = rateLimitMap.get(ip) || { count: 0, start: now };

    if (now - entry.start > RATE_LIMIT_WINDOW_MS) {
        // Nouvelle fenêtre
        rateLimitMap.set(ip, { count: 1, start: now });
        return false;
    }

    if (entry.count >= RATE_LIMIT_MAX) return true;

    entry.count++;
    rateLimitMap.set(ip, entry);
    return false;
}

exports.handler = async (event) => {
    // ── CORS ────────────────────────────────────────────────────────────
    const origin = event.headers['origin'] || '';
    if (origin !== ALLOWED_ORIGIN) {
        return { statusCode: 403, body: 'Forbidden' };
    }

    // ── Méthode ─────────────────────────────────────────────────────────
    if (event.httpMethod !== 'POST') {
        return { statusCode: 405, body: 'Method Not Allowed' };
    }

    // ── Rate limiting ────────────────────────────────────────────────────
    const ip = event.headers['x-forwarded-for']?.split(',')[0] || 'unknown';
    if (isRateLimited(ip)) {
        return {
            statusCode: 429,
            body: JSON.stringify({ error: 'Too many requests' }),
            headers: { 'Content-Type': 'application/json' }
        };
    }

    // ── Validation du body ───────────────────────────────────────────────
    let payload;
    try {
        payload = JSON.parse(event.body);
    } catch {
        return { statusCode: 400, body: 'Invalid JSON' };
    }

    // Vérifier que le payload contient bien les champs attendus (pas d'injection)
    if (!payload.embeds || !Array.isArray(payload.embeds)) {
        return { statusCode: 400, body: 'Invalid payload structure' };
    }

    // Nettoyer les champs pour éviter l'injection de contenu malveillant
    const safePayload = {
        embeds: payload.embeds.map(embed => ({
            title: String(embed.title || '').slice(0, 256),
            description: String(embed.description || '').slice(0, 4096),
            color: typeof embed.color === 'number' ? embed.color : 0,
            thumbnail: embed.thumbnail?.url ? { url: String(embed.thumbnail.url).slice(0, 512) } : undefined,
            fields: Array.isArray(embed.fields) ? embed.fields.slice(0, 25).map(f => ({
                name: String(f.name || '').slice(0, 256),
                value: String(f.value || '').slice(0, 1024),
                inline: !!f.inline
            })) : [],
            timestamp: new Date().toISOString()
        }))
    };

    // ── Webhook URL depuis les variables d'environnement ─────────────────
    const webhookUrl = process.env.WEBHOOK_CONNEXIONS;
    if (!webhookUrl) {
        return { statusCode: 500, body: 'Webhook not configured' };
    }

    // ── Envoi à Discord ──────────────────────────────────────────────────
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
    } catch (err) {
        return { statusCode: 502, body: 'Network error' };
    }
};
