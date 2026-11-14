import { describe, it, expect } from 'vitest';
import { decodeXmlEntities, sanitizeComponentName, sanitizeEdgeLabel } from './clean-text';

describe('clean-text universal sanitization', () => {
  it('decodes numeric and hex XML entities accurately', () => {
    expect(decodeXmlEntities('Postgres&#xa;RDS')).toBe('Postgres\nRDS');
    expect(decodeXmlEntities('Line1&#0010;Line2')).toBe('Line1\nLine2');
    expect(decodeXmlEntities('Orders&#XA;Microservice')).toBe('Orders\nMicroservice');
    expect(decodeXmlEntities('&lt;b&gt;API&lt;/b&gt; &amp; Gateway')).toBe('API & Gateway');
    expect(sanitizeComponentName('&lt;b&gt;API&lt;/b&gt; &amp; Gateway')).toBe('API & Gateway');
  });

  it('extracts clean component name from draw.io multiline attributes', () => {
    const raw = 'Production PostgreSQL RDS&#xa;(Encrypted: Yes | Multi-AZ: Yes)&#xa;SSL / TLS Enforced: Disabled';
    expect(sanitizeComponentName(raw)).toBe('Production PostgreSQL RDS');
  });

  it('strips finding descriptions and metadata inside parentheticals', () => {
    expect(sanitizeComponentName('Public Application Load Balancer (Missing WAF Integration)')).toBe('Public Application Load Balancer');
    expect(sanitizeComponentName('Core Order API Service (EC2 Cluster)')).toBe('Core Order API Service');
  });

  it('strips noisy prefixes like Lateral Pivot and Remediate', () => {
    expect(sanitizeComponentName('Lateral Pivot: Internet Gateway (IGW)')).toBe('Internet Gateway (IGW)');
    expect(sanitizeComponentName('Crown Jewel Data Exfiltration: Database')).toBe('Database');
    expect(sanitizeComponentName('Remediate: Unsegmented Ingress Exposure: Production RDS')).toBe('Production RDS');
  });

  it('sanitizes edge labels and strips entity line breaks', () => {
    const rawEdge = 'SQL Query Stream&#xa;(Port 5432 - No TLS/mTLS)';
    expect(sanitizeEdgeLabel(rawEdge)).toBe('SQL Query Stream');
  });
});
