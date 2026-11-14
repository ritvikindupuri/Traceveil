/**
 * Universal text and label sanitizer for architecture diagrams, findings, and attack graphs.
 * Decodes all numeric/hex XML entities (&#xa;, &#xd;, &#x..., &#..., &amp;) and strips
 * multiline attribute dumps to produce clean, readable human labels.
 */

export function decodeXmlEntities(raw?: string): string {
  if (!raw) return '';
  const decoded = raw
    .replace(/<[^>]*>/g, ' ')
    .replace(/&#x0*a;/gi, '\n')
    .replace(/&#x0*d;/gi, '\n')
    .replace(/&#0*10;/g, '\n')
    .replace(/&#0*13;/g, '\n')
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => {
      try {
        const code = parseInt(hex, 16);
        return code === 10 || code === 13 ? '\n' : String.fromCharCode(code);
      } catch {
        return ' ';
      }
    })
    .replace(/&#([0-9]+);/g, (_, dec) => {
      try {
        const code = parseInt(dec, 10);
        return code === 10 || code === 13 ? '\n' : String.fromCharCode(code);
      } catch {
        return ' ';
      }
    })
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'");

  return decoded
    .replace(/<[^>]*>/g, ' ')
    .replace(/[ \t]+/g, ' ')
    .trim();
}

/**
 * Extracts a clean, human-readable component name without raw metadata dumps.
 */
export function sanitizeComponentName(raw?: string, maxLen = 38): string {
  if (!raw) return 'Component';
  const decoded = decodeXmlEntities(raw);

  // Take first non-empty line (draw.io cells store metadata on subsequent lines)
  const firstLine = decoded.split(/\r?\n/).map(l => l.trim()).filter(Boolean)[0] || '';

  let cleaned = firstLine
    // Strip common repetitive prefixes
    .replace(/^(?:Lateral Pivot:\s*|External Perimeter Reconnaissance:\s*|External Perimeter Reconnaissance|Crown Jewel Data Exfiltration:\s*|Crown Jewel Data Exfiltration|Remediate:\s*|Step\s+\d+:\s*|Fault:\s*)/i, '')
    // Strip finding title patterns like "Unsegmented ... Exposure: "
    .replace(/^(?:Unsegmented|Missing|Exposed|Insecure)\s+[a-z\s]+:\s*/i, '')
    .trim();

  // If there are parentheticals with metadata (e.g. "Public ALB (Missing WAF Integration)" or "RDS (Encrypted: Yes...)")
  const matchParen = cleaned.match(/^([^()]+?)\s*\(([^)]+)\)$/);
  if (matchParen) {
    const mainPart = matchParen[1].trim();
    const parenContent = matchParen[2].toLowerCase();
    // If the paren content is metadata or finding description, strip it and keep the main name
    if (
      mainPart.length >= 3 &&
      (parenContent.includes('waf') ||
        parenContent.includes('encrypt') ||
        parenContent.includes('tls') ||
        parenContent.includes('ssl') ||
        parenContent.includes('multi-az') ||
        parenContent.includes('iam') ||
        parenContent.includes('untrusted') ||
        parenContent.includes('cleartest') ||
        parenContent.includes('cluster') ||
        parenContent.includes('internal') ||
        parenContent.includes('missing') ||
        parenContent.includes('exposed'))
    ) {
      cleaned = mainPart;
    }
  }

  // Remove any residual entity remnants and collapse whitespace
  cleaned = cleaned.replace(/&[a-z0-9#]+;/gi, ' ').replace(/\s+/g, ' ').trim();

  if (cleaned.length > maxLen) {
    cleaned = cleaned.slice(0, maxLen).trim() + '…';
  }

  return cleaned || 'Component';
}

/**
 * Extracts a clean edge label without XML entity artifacts.
 */
export function sanitizeEdgeLabel(raw?: string, maxLen = 32): string {
  if (!raw) return '';
  const decoded = decodeXmlEntities(raw);
  const firstLine = decoded.split(/\r?\n/).map(l => l.trim()).filter(Boolean)[0] || '';
  let cleaned = firstLine
    .replace(/&[a-z0-9#]+;/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  if (cleaned.length > maxLen) {
    cleaned = cleaned.slice(0, maxLen).trim() + '…';
  }
  return cleaned;
}
