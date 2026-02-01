/**
 * AgentShield — Prompt Injection Scanner for AI Agents
 * 150+ detection patterns across 9 categories
 * 
 * @example
 * const { scan, scanQuick } = require('agentshield');
 * const result = scan("Ignore all previous instructions");
 * if (result.threats.length > 0) console.log("THREAT DETECTED:", result.summary);
 */

const rules = require('./rules.json');

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

/**
 * Scan text for prompt injection threats
 * @param {string} text - Text to scan
 * @param {object} [options] - Scan options
 * @param {string[]} [options.categories] - Only scan these categories (default: all)
 * @param {string} [options.minSeverity] - Minimum severity to report: 'low'|'medium'|'high'|'critical' (default: 'medium')
 * @returns {ScanResult}
 */
function scan(text, options = {}) {
  if (!text || typeof text !== 'string') {
    return { clean: true, threats: [], summary: 'No text to scan', severity: null, categories: [] };
  }

  const minSev = options.minSeverity || 'medium';
  const minSevOrder = SEVERITY_ORDER[minSev] ?? 2;
  const categoryFilter = options.categories ? new Set(options.categories) : null;

  const threats = [];

  for (const [catKey, catData] of Object.entries(rules.categories)) {
    if (categoryFilter && !categoryFilter.has(catKey)) continue;

    for (const rule of catData.patterns) {
      const sevOrder = SEVERITY_ORDER[rule.severity] ?? 2;
      if (sevOrder > minSevOrder) continue;

      try {
        const regex = new RegExp(rule.pattern, 'i');
        if (regex.test(text)) {
          threats.push({
            id: rule.id,
            category: catKey,
            severity: rule.severity,
            description: rule.description,
            pattern: rule.pattern,
          });
        }
      } catch (e) {
        // Skip invalid regex
      }
    }
  }

  // Sort by severity
  threats.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 2) - (SEVERITY_ORDER[b.severity] ?? 2));

  const highestSeverity = threats.length > 0 ? threats[0].severity : null;
  const uniqueCategories = [...new Set(threats.map(t => t.category))];

  return {
    clean: threats.length === 0,
    threats,
    count: threats.length,
    severity: highestSeverity,
    categories: uniqueCategories,
    summary: threats.length === 0
      ? 'No threats detected'
      : `${threats.length} threat${threats.length > 1 ? 's' : ''} detected (${highestSeverity}): ${uniqueCategories.join(', ')}`,
  };
}

/**
 * Quick boolean check — is this text suspicious?
 * @param {string} text - Text to scan
 * @returns {boolean} true if threats detected
 */
function scanQuick(text) {
  return !scan(text, { minSeverity: 'high' }).clean;
}

/**
 * Get all available categories
 * @returns {string[]}
 */
function getCategories() {
  return Object.keys(rules.categories);
}

/**
 * Get rule count
 * @returns {number}
 */
function getRuleCount() {
  let count = 0;
  for (const cat of Object.values(rules.categories)) {
    count += cat.patterns.length;
  }
  return count;
}

module.exports = { scan, scanQuick, getCategories, getRuleCount };
