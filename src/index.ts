import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { Octokit } from "@octokit/core";
import {
  createAckEvent,
  createDoneEvent,
  createErrorsEvent,
  createTextEvent,
  getUserMessage,
  verifyAndParseRequest,
  prompt,
  createConfirmationEvent
} from "@copilot-extensions/preview-sdk";
import * as path from "path";
import * as fs from "fs";
import { stream } from "hono/streaming";
import Fuse from 'fuse.js';

const mockProjectData = {
  data: [
    {
      attributes: {
        build_args: {
          root_workspace: 'text',
        },
        business_criticality: ['medium'],
        created: '2021-05-29T09:50:54.014Z',
        environment: ['external', 'hosted'],
        lifecycle: ['production'],
        name: 'madrym/parakletos',
        origin: 'github',
        read_only: false,
        settings: {
          auto_dependency_upgrade: {
            ignored_dependencies: ['typescript'],
            is_enabled: true,
            is_major_upgrade_enabled: true,
            limit: 10,
            minimum_age: 365,
          },
          auto_remediation_prs: {
            is_backlog_prs_enabled: true,
            is_fresh_prs_enabled: true,
            is_patch_remediation_enabled: true,
          },
          manual_remediation_prs: {
            is_patch_remediation_enabled: true,
          },
          pull_request_assignment: {
            assignees: ['my-github-username'],
            is_enabled: true,
            type: 'auto',
          },
          pull_requests: {
            fail_only_for_issues_with_fix: true,
            policy: 'all',
            severity_threshold: 'high',
          },
          recurring_tests: {
            frequency: 'daily',
          },
        },
        status: 'active',
        tags: [
          {
            key: 'tag-key',
            value: 'tag-value',
          },
        ],
        target_file: 'package.json',
        target_reference: 'main',
        target_runtime: 'text',
        type: 'npm',
      },
      id: '123e4567-e89b-12d3-a456-426614174000',
      meta: {
        cli_monitored_at: '2021-05-29T09:50:54.014Z',
        latest_dependency_total: {
          total: 0,
          updated_at: '2024-10-28T09:42:08.079Z',
        },
        latest_issue_counts: {
          critical: 0,
          high: 0,
          low: 0,
          medium: 0,
          updated_at: '2024-10-28T09:42:08.079Z',
        },
      },
      relationships: {
        organization: {
          data: {
            id: '4a72d1db-b465-4764-99e1-ecedad03b06a',
            type: 'resource',
          },
        },
        target: {
          data: {
            id: '4a72d1db-b465-4764-99e1-ecedad03b06a',
            type: 'resource',
          },
        },
      },
      type: 'project',
    },
  ],
  jsonapi: {
    version: '1.0',
  },
};

const mockIssuesData = {
  data: {
    attributes: {
      classes: [
        {
          id: 'CWE-190',
          source: 'CWE',
          type: 'weakness',
        },
      ],
      coordinates: [
        {
          is_fixable_manually: false,
          is_fixable_snyk: false,
          is_fixable_upstream: true,
          is_patchable: false,
          is_pinnable: false,
          is_upgradeable: true,
          reachability: 'reachable',
          remedies: [
            {
              correlation_id: '12345',
              description: 'Upgrade to next@14.2.10 to resolve the issue',
              meta: {
                schema_version: '1.0',
              },
              type: 'upgrade',
            },
          ],
          representations: [
            {
              resourcePath: 'parakletos@0.1.0 › next@14.2.8',
            },
          ],
        },
      ],
      created_at: '2024-10-28T09:43:33.006Z',
      description:
        'Affected versions of this package are vulnerable to Acceptance of Extraneous Untrusted Data With Trusted Data...',
      effective_severity_level: 'high',
      ignored: false,
      key: '24018479-6bb1-4196-a41b-e54c7c5dcc82:1',
      problems: [
        {
          id: 'SNYK-JS-NEXT-123456',
          source: 'snyk',
          type: 'rule',
        },
      ],
      resolution: {
        details: 'Upgrade to next@14.2.10',
        resolved_at: '2024-10-28T09:43:33.006Z',
        type: 'disappeared',
      },
      risk: {
        factors: [
          {
            name: 'deployed',
            updated_at: '2023-09-07T13:36:37Z',
            value: true,
          },
        ],
        score: {
          model: 'v4',
          value: 649,
        },
      },
      status: 'open',
      title: 'Acceptance of Extraneous Untrusted Data With Trusted Data',
      tool: 'snyk://npm-deps',
      type: 'npm',
      updated_at: '2024-10-28T09:43:33.006Z',
    },
    id: '73832c6c-19ff-4a92-850c-2e1ff2800c16',
  },
  jsonapi: {
    version: '1.0',
  },
  included: [
    {
      attributes: {
        classes: [
          {
            id: 'CWE-79',
            source: 'CWE',
            type: 'weakness',
          },
        ],
        coordinates: [
          {
            is_fixable_manually: false,
            is_fixable_snyk: false,
            is_fixable_upstream: true,
            is_patchable: false,
            is_pinnable: false,
            is_upgradeable: true,
            reachability: 'reachable',
            remedies: [
              {
                correlation_id: '67890',
                description: 'Upgrade to @clerk/nextjs@5.7.2 to resolve the issue',
                meta: {
                  schema_version: '1.0',
                },
                type: 'upgrade',
              },
            ],
            representations: [
              {
                resourcePath:
                  'parakletos@0.1.0 › @clerk/nextjs@5.6.0 › @clerk/backend@1.13.2 › cookie@0.5.0',
              },
            ],
          },
        ],
        created_at: '2024-10-28T09:43:33.006Z',
        description:
          'Affected versions of this package are vulnerable to Cross-site Scripting (XSS)...',
        effective_severity_level: 'medium',
        ignored: false,
        key: '24018479-6bb1-4196-a41b-e54c7c5dcc82:2',
        problems: [
          {
            id: 'SNYK-JS-COOKIE-789012',
            source: 'snyk',
            type: 'rule',
          },
        ],
        resolution: {
          details: 'Upgrade to @clerk/nextjs@5.7.2',
          resolved_at: '2024-10-28T09:43:33.006Z',
          type: 'disappeared',
        },
        risk: {
          factors: [
            {
              name: 'deployed',
              updated_at: '2023-09-07T13:36:37Z',
              value: true,
            },
          ],
          score: {
            model: 'v4',
            value: 601,
          },
        },
        status: 'open',
        title: 'Cross-site Scripting (XSS)',
        tool: 'snyk://npm-deps',
        type: 'npm',
        updated_at: '2024-10-28T09:43:33.006Z',
      },
      id: '73832c6c-19ff-4a92-850c-2e1ff2800c17',
    },
  ],
};

// Add new interface for CodeQL alert types
interface CodeQLAlert {
  number: number;
  state: "open" | "fixed" | "dismissed";
  title: string;  // From security_severity_level
  severity: string;  // From security_severity_level
  description: string;  // From message
  most_recent_instance?: {
    location?: {
      path?: string;
      start_line?: number;
      end_line?: number;
      start_column?: number;
      end_column?: number;
      snippet?: string;  // Make snippet optional
    };
  };
  // Add missing fields from API
  created_at: string;
  updated_at?: string;
  url: string;
  html_url: string;
  instances_url: string;
  fixed_at?: string | null;
}

// Add new interface for command intents
interface CommandIntent {
  name: string;
  handler: Function;
  patterns: string[];
  description: string;
}

// Add new constant for command intents
const COMMAND_INTENTS: CommandIntent[] = [
  {
    name: 'listVulnerabilities',
    handler: handleCodeQLList,
    description: 'Shows a list of security vulnerabilities in your codebase',
    patterns: [
      'list codeql',
      'show vulnerabilities',
      'show my vulnerabilities',
      'show security issues',
      'list security problems',
      'display vulnerabilities',
      'what vulnerabilities',
      'security scan results',
      'show me my vulnerabilities',
      'security issues',
      'code scanning alerts',
      'security alerts',
      'show security status',
      'vulnerability report',
      'security overview',
      'vulnerabilities',
      'security scan',
      'security check'
    ]
  },
  {
    name: 'fixVulnerability',
    handler: handleVulnerabilityFix,
    description: 'Provides guidance on fixing a specific vulnerability',
    patterns: [
      'fix the vulnerability',
      'fix vulnerability',
      'repair vulnerability',
      'resolve security issue',
      'fix security problem',
      'how to fix',
      'solve vulnerability',
      'patch security issue',
      'remediate vulnerability',
      'security fix',
      'vulnerability solution',
      'fix the vulnerability "'
    ]
  }
];

// Get the owner and repo from the .git/config file
async function getRepoInfoFromGitConfig() {
  const gitConfigPath = path.join(process.cwd(), '.git', 'config');
  const gitConfigContent = fs.readFileSync(gitConfigPath, 'utf8');
  const repoUrlMatch = gitConfigContent.match(/url = (.+)/);

  if (repoUrlMatch) {
    const repoUrl = repoUrlMatch[1];
    const repoMatch = repoUrl.match(/github\.com[:\/]([^\/]+)\/([^\/]+)\.git/);
    if (repoMatch) {
      const [, owner, repo] = repoMatch;
      return { owner, repo };
    }
  }
  throw new Error('Could not determine repository information from .git/config');
}

// Add new function to format CodeQL alerts
function formatCodeQLAlerts(alerts: CodeQLAlert[]) {
  const severityOrder = ['critical', 'high', 'medium', 'low'];
  const groupedAlerts = alerts.reduce((acc: { [key: string]: CodeQLAlert[] }, alert) => {
    acc[alert.severity] = acc[alert.severity] || [];
    acc[alert.severity].push(alert);
    return acc;
  }, {});

  let response = `# Security Vulnerabilities Summary\n\n`;
  
  // Add summary section
  let totalVulns = 0;
  const summaryItems = severityOrder.map(severity => {
    const count = groupedAlerts[severity]?.length || 0;
    totalVulns += count;
    return count > 0 ? `**${count}** ${severity}` : null;
  }).filter(Boolean);
  
  response += `Found ${totalVulns} total vulnerabilities: ${summaryItems.join(', ')}\n\n`;

  // Create table for high and critical vulnerabilities
  if (totalVulns > 0) {
    response += `| Severity | Title | Location | Fix Command (Copy into the chat) |\n`;
    response += `|:--------:|:-------:|:---------:|:------------|\n`;
    
    ['critical', 'high'].forEach(severity => {
      const severityAlerts = groupedAlerts[severity] || [];
      severityAlerts.slice(0, 3).forEach(alert => {
        const location = alert.most_recent_instance?.location;
        const locationStr = location ? `${location.path}:${location.start_line}` : 'N/A';
        const uniqueId = `${alert.title} in ${locationStr}`;
        
        response += `| **${severity[0].toUpperCase()}** | ${alert.title} | ${locationStr} | \`fix the vulnerability "${uniqueId}"\` |\n`;
      });
    });
  }

  // Add note about medium/low severity issues
  const mediumCount = groupedAlerts['medium']?.length || 0;
  const lowCount = groupedAlerts['low']?.length || 0;
  if (mediumCount || lowCount) {
    response += `\n---\n`;
    response += `ℹ️ There are also `;
    if (mediumCount) response += `**${mediumCount}** medium `;
    if (mediumCount && lowCount) response += `and `;
    if (lowCount) response += `**${lowCount}** low `;
    response += `severity issues. Use \`expand medium\` or \`expand low\` to view them.\n`;
  }

  return response;
}

// Add new function to generate fix suggestions
async function generateCodeQLFix(alert: CodeQLAlert, token: string) {
  const location = alert.most_recent_instance?.location;
  
  let codeContext = '';
  if (location?.path) {
    try {
      // Read the actual file content
      const filePath = path.join(process.cwd(), location.path);
      const fileContent = fs.readFileSync(filePath, 'utf8');
      
      // Get the entire file content
      const lines = fileContent.split('\n');
      const startLine = location.start_line || 1; // Start from the first line
      const endLine = location.end_line || lines.length; // Go to the last line
      
      codeContext = lines.slice(startLine - 1, endLine).join('\n');
    } catch (error) {
      console.error("Error reading file:", error);
      codeContext = location.snippet || 'File content not available';
    }
  }

  const fixPrompt = `You are a security expert. Please analyze this security vulnerability and provide a detailed fix.
    
Context:
- File: ${location?.path}
- Lines: ${location?.start_line}-${location?.end_line}
- Title: ${alert.title}
- Severity: ${alert.severity}
- Description: ${alert.description}

Relevant code context:
\`\`\`
${codeContext}
\`\`\`

Please provide:
1. A clear explanation of why this code is vulnerable
2. A specific code fix with before/after comparison
3. Additional security best practices to prevent similar issues (Limit to 2-3 bullet points)
4. Any testing recommendations to verify the fix (Limit to 2-3 bullet points)

Focus on the specific lines of code shown and provide concrete, actionable fixes.
Make your response concise and to the point.
`;

  try {
    const { message } = await prompt(fixPrompt, {
      model: "gpt-4",
      token,
    });
    return message.content;
  } catch (error) {
    console.error("Error generating fix:", error);
    return "An error occurred while generating the fix suggestion.";
  }
}

const searchablePatterns = COMMAND_INTENTS.flatMap(intent =>
  intent.patterns.map(pattern => ({
    pattern,
    intent: intent.name,
    handler: intent.handler,
    description: intent.description
  }))
);

const fuseOptions = {
  keys: ['pattern'],
  threshold: 0.6,
  includeScore: true,
  minMatchCharLength: 3,
  shouldSort: true,
  distance: 200,
  useExtendedSearch: true,
  ignoreLocation: true,
  findAllMatches: true,
  location: 0,
  isCaseSensitive: false
};

const fuse = new Fuse(searchablePatterns, fuseOptions);

function findMatchingIntent(userInput: string): { 
  handler: Function;
  matchedPattern: string;
  score: number;
  description: string;
  userInput: string;
} | null {
  const normalizedInput = userInput.toLowerCase().trim();
  
  // Special case for fix commands
  if (normalizedInput.startsWith('fix the vulnerability "')) {
    return {
      handler: handleVulnerabilityFix,
      matchedPattern: 'fix the vulnerability',
      score: 0,
      description: 'Provides guidance on fixing a specific vulnerability',
      userInput: userInput
    };
  }

  // Regular fuzzy matching for other commands
  const results = fuse.search(normalizedInput);
  
  console.log('User input:', normalizedInput);
  console.log('Search results:', results.slice(0, 3).map(r => ({
    pattern: r.item.pattern,
    score: r.score
  })));

  if (results.length > 0 && results[0].score && results[0].score < 0.6) {
    console.log('Matched intent:', results[0].item);
    return {
      handler: results[0].item.handler,
      matchedPattern: results[0].item.pattern,
      score: results[0].score as number,
      description: results[0].item.description,
      userInput: userInput
    };
  }
  return null;
}

function createHelpMessage(): string {
  return `I didn't quite understand that command. Here are some things you can ask me:

${COMMAND_INTENTS.map(intent => `• ${intent.description}
  Example: "${intent.patterns[0]}"`).join('\n\n')}

You can try one of these commands or rephrase your request.`;
}

const app = new Hono();

app.get("/", (c) => {
  return c.text("Welcome to the Copilot Extension template! 👋");
});

async function handleCodeQLList(stream: any, octokit: Octokit, tokenForUser: string) {
  const { owner, repo } = await getRepoInfoFromGitConfig();
  const { data: alerts } = await octokit.request('GET /repos/{owner}/{repo}/code-scanning/alerts', {
    owner,
    repo,
    headers: { 'X-GitHub-Api-Version': '2022-11-28' }
  });

  const mappedAlerts = alerts.map(alert => ({
    ...alert,
    title: alert.rule?.description || 'Unknown',
    severity: alert.rule?.security_severity_level || 'low',
    description: typeof alert.most_recent_instance?.message === 'string' 
      ? alert.most_recent_instance.message 
      : alert.most_recent_instance?.message?.text || 'No description available'
  }));

  // First show the summary
  const summaryResponse = formatCodeQLAlerts(mappedAlerts);
  stream.write(createTextEvent(summaryResponse));

  // For each critical and high severity vulnerability, create a confirmation event
  mappedAlerts
    .filter(alert => ['critical', 'high'].includes(alert.severity))
    .forEach((alert, index) => {
      const location = alert.most_recent_instance?.location;
      const locationStr = location ? `${location.path}:${location.start_line}` : 'N/A';
      
      stream.write(createConfirmationEvent({
        id: `vuln-${alert.number}`,
        title: `**(${alert.severity.toUpperCase()}) ${alert.title}**`,
        message: `**Description**: ${alert.description}\n\n` +
        `**Location**: \`${locationStr}\`\n\n` +
        `Would you like to get fix suggestions for this vulnerability?`,
        metadata: {
          alertId: alert.number,
          location: locationStr,
          severity: alert.severity,
          title: alert.title
        }
      }));
    });
}

async function handleVulnerabilityFix(stream: any, userPrompt: string, octokit: Octokit, tokenForUser: string) {
  const { owner, repo } = await getRepoInfoFromGitConfig();
  const { data: alerts } = await octokit.request('GET /repos/{owner}/{repo}/code-scanning/alerts', {
    owner,
    repo,
    headers: { 'X-GitHub-Api-Version': '2022-11-28' }
  });

  const mappedAlerts = alerts.map(alert => ({
    ...alert,
    title: alert.rule?.description || 'Unknown',
    severity: alert.rule?.security_severity_level || 'low',
    description: typeof alert.most_recent_instance?.message === 'string' 
      ? alert.most_recent_instance.message 
      : alert.most_recent_instance?.message?.text || 'No description available'
  }));

  const vulnIdentifier = userPrompt.match(/"([^"]+)"/)?.[1] || "";
  const targetAlert = mappedAlerts.find(alert => {
    const location = alert.most_recent_instance?.location;
    if (!location) return false;
    const locationStr = `${location.path}:${location.start_line}`;
    return vulnIdentifier.includes(locationStr);
  });

  if (targetAlert) {
    const fixSuggestion = await generateCodeQLFix(targetAlert, tokenForUser);
    stream.write(createTextEvent(fixSuggestion));
  } else {
    stream.write(createErrorsEvent([{
      type: "agent",
      message: "No matching vulnerability found.",
      code: "VULN_NOT_FOUND",
      identifier: "vuln_not_found",
    }]));
  }
}

async function handleDefaultPrompt(stream: any, userPrompt: string, user: any, tokenForUser: string) {
  const { message } = await prompt(userPrompt, {
    model: "gpt-4",
    token: tokenForUser,
  });
  stream.write(createTextEvent(`Hi ${user.data.login}!\n\n`));
  
  stream.write(createTextEvent(message.content));
  stream.write(createDoneEvent());
}

async function handleUserCommand(stream: any, userPrompt: string, octokit: Octokit, tokenForUser: string, user: any) {
  const matchedIntent = findMatchingIntent(userPrompt);
  
  if (matchedIntent) {
    console.log(`Matched intent: ${matchedIntent.matchedPattern} (score: ${matchedIntent.score})`);

    if (matchedIntent.score > 0.3) {
      stream.write(createTextEvent(
        `I'll interpret that as "${matchedIntent.matchedPattern}". ` +
        `If this isn't what you meant, please try rephrasing your request.\n\n`
      ));
    }

    if (matchedIntent.handler === handleVulnerabilityFix) {
      await matchedIntent.handler(stream, matchedIntent.userInput, octokit, tokenForUser);
    } else {
      await matchedIntent.handler(stream, octokit, tokenForUser);
    }
  } else {
    await handleDefaultPrompt(stream, userPrompt, user, tokenForUser);
  }
}

// Update the main app.post handler to use a switch statement
app.post("/", async (c) => {
  // Identify the user, using the GitHub API token provided in the request headers.
  const tokenForUser = c.req.header("X-GitHub-Token") ?? "";

  const body = await c.req.text();
  const signature = c.req.header("github-public-key-signature") ?? "";
  const keyID = c.req.header("github-public-key-identifier") ?? "";

  const { isValidRequest, payload } = await verifyAndParseRequest(
    body,
    signature,
    keyID,
    {
      token: tokenForUser,
    }
  );

  if (!isValidRequest) {
    console.error("Request verification failed");
    c.header("Content-Type", "text/plain");
    c.status(401);
    c.text("Request could not be verified");
    return;
  }

  if (!tokenForUser) {
    return c.text(
      createErrorsEvent([
        {
          type: "agent",
          message: "No GitHub token provided in the request headers.",
          code: "MISSING_GITHUB_TOKEN",
          identifier: "missing_github_token",
        },
      ])
    );
  }

  c.header("Content-Type", "text/html");
  c.header("X-Content-Type-Options", "nosniff");

  return stream(c, async (stream) => {
    try {
      stream.write(createAckEvent());

      const octokit = new Octokit({ auth: tokenForUser });
      const user = await octokit.request("GET /user");
      const userPrompt = getUserMessage(payload);

      await handleUserCommand(stream, userPrompt, octokit, tokenForUser, user);

      stream.write(createDoneEvent());
    } catch (error) {
      stream.write(createErrorsEvent([{
        type: "agent",
        message: error instanceof Error ? error.message : "Unknown error",
        code: "PROCESSING_ERROR",
        identifier: "processing_error",
      }]));
    }
  });
});

const port = 3000;
console.log(`Server is running on port ${port}`);

serve({
  fetch: app.fetch,
  port,
});
