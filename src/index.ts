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
  prompt
} from "@copilot-extensions/preview-sdk";
import * as path from "path";
import * as fs from "fs";

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
      
      // Get a few lines before and after the vulnerability
      const lines = fileContent.split('\n');
      const startLine = Math.max(0, (location.start_line || 1) - 5);
      const endLine = Math.min(lines.length, (location.end_line || location.start_line || 1) + 5);
      
      codeContext = lines.slice(startLine, endLine).join('\n');
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
3. Additional security best practices to prevent similar issues
4. Any testing recommendations to verify the fix

Focus on the specific lines of code shown and provide concrete, actionable fixes.`;

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

const app = new Hono();

app.get("/", (c) => {
  return c.text("Welcome to the Copilot Extension template! 👋");
});

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

  const octokit = new Octokit({ auth: tokenForUser });
  const user = await octokit.request("GET /user");
  const userPrompt = getUserMessage(payload);

  async function analyzeCodeForVulnerabilities(code: string, token: string) {
    const userPrompt = `Please analyze the following code for potential vulnerabilities:\n\n${code}`;

    try {
      const { message } = await prompt(userPrompt, {
        model: "gpt-4",
        token,
      });

      return message.content;
    } catch (error) {
      console.error("Error analyzing code:", error);
      return "An error occurred while analyzing the code.";
    }
  }

  // Check if the prompt is asking for vulnerability analysis
  if (userPrompt.toLowerCase().includes("vulnerabilities")) {
    const codeToAnalyze = userPrompt.replace(/vulnerabilities/gi, "").trim();
    
    if (codeToAnalyze) {
      const analysis = await analyzeCodeForVulnerabilities(codeToAnalyze, tokenForUser);
      
      return c.text(
        createAckEvent() +
        createTextEvent(analysis) +
        createDoneEvent()
      );
    } else {
      return c.text(
        createErrorsEvent([
          {
            type: "agent",
            message: "No code provided for vulnerability analysis.",
            code: "NO_CODE_PROVIDED",
            identifier: "no_code_provided",
          },
        ])
      );
    }
  }

  // Check if the prompt is asking for Dependabot alerts
  if (userPrompt.toLowerCase().includes("dependabot alerts")) {
    const { owner, repo } = await getRepoInfoFromGitConfig();
    
    if (repo) {
      try {
        const { data: alerts } = await octokit.request('GET /repos/{owner}/{repo}/dependabot/alerts', {
          owner,
          repo,
          headers: {
            'X-GitHub-Api-Version': '2022-11-28'
          }
        });

        let response = `Dependabot alerts for ${owner}/${repo}:\n\n`;
        if (alerts.length === 0) {
          response += "No Dependabot alerts found.";
        } else {
          alerts.forEach((alert: any, index: number) => {
            response += `${index + 1}. ${alert.security_advisory.summary}\n`;
            response += `   Severity: ${alert.security_advisory.severity}\n`;
            response += `   Package: ${alert.security_vulnerability.package.name}\n`;
            response += `   Vulnerable versions: ${alert.security_vulnerability.vulnerable_version_range}\n\n`;
          });
        }

        return c.text(
          createAckEvent() +
          createTextEvent(response) +
          createDoneEvent()
        );
      } catch (error) {
        return c.text(
          createErrorsEvent([
            {
              type: "agent",
              message: "Error fetching Dependabot alerts: " + (error instanceof Error ? error.message : String(error)),
              code: "GITHUB_API_ERROR",
              identifier: "github_api_error",
            },
          ])
        );
      }
    } else {
      return c.text(
        createErrorsEvent([
          {
            type: "agent",
            message: "Invalid GitHub repository URL provided.",
            code: "INVALID_REPO_URL",
            identifier: "invalid_repo_url",
          },
        ])
      );
    }
  }

  // Add new function to format Snyk issues
  function formatSnykIssues(projectData: any, issuesData: any) {
    const issues = [issuesData.data, ...issuesData.included];
    let response = `# Security Vulnerabilities Report\n\n`;
    response += `**Project:** ${projectData.data[0].attributes.name}\n\n`;
    response += `Found ${issues.length} vulnerabilities:\n\n`;
    
    // Create table header
    response += `| # | Vulnerability | Severity | Package | Status | Description |\n`;
    response += `|---|--------------|-----------|---------|---------|-------------|\n`;
    
    // Add each issue as a table row
    issues.forEach((issue: any, index: number) => {
      const attr = issue.attributes;
      const description = attr.description.substring(0, 100) + '...'; // Truncate long descriptions
      
      response += `| ${index + 1} | ${attr.title} | \`${attr.effective_severity_level}\` | \`${attr.coordinates[0].representations[0].resourcePath}\` | ${attr.status} | ${description} |\n`;
    });
    
    // Add remediation note
    response += `\n> 💡 Type "fix vuln" to get detailed remediation steps.\n`;
    
    return response;
  }

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

  // Add new function to get remediation steps
  async function getRemediationSteps(issues: any, token: string) {
    const remediationPrompt = `Please provide step-by-step remediation instructions for the following vulnerabilities...`;

    try {
      const { message } = await prompt(remediationPrompt, {
        model: "gpt-4",
        token,
      });
      return message.content;
    } catch (error) {
      console.error("Error getting remediation steps:", error);
      return "An error occurred while generating remediation steps.";
    }
  }

  // Check if the prompt is asking for Snyk vulnerabilities
  if (userPrompt.toLowerCase().includes("snyk")) {
    // Simulate API call using mock data
    const response = formatSnykIssues(mockProjectData, mockIssuesData);
    
    return c.text(
      createAckEvent() +
      createTextEvent(response) +
      createDoneEvent()
    );
  }

  // Check if the prompt is asking for vulnerability fixes
  if (userPrompt.toLowerCase().includes("fix vuln")) {
    const remediationSteps = await getRemediationSteps(mockIssuesData, tokenForUser);
    
    return c.text(
      createAckEvent() +
      createTextEvent(remediationSteps) +
      createDoneEvent()
    );
  }

  // Check if the prompt is asking for CodeQL alerts
  if (userPrompt.toLowerCase().includes("list codeql")) {
    const { owner, repo } = await getRepoInfoFromGitConfig();
    
    try {
      const { data: alerts } = await octokit.request('GET /repos/{owner}/{repo}/code-scanning/alerts', {
        owner,
        repo,
        headers: {
          'X-GitHub-Api-Version': '2022-11-28'
        }
      });

      const mappedAlerts: CodeQLAlert[] = alerts.map(alert => ({
        ...alert,
        title: alert.rule?.description || 'Unknown',
        severity: alert.rule?.security_severity_level || 'unknown',
        description: typeof alert.most_recent_instance?.message === 'string' 
          ? alert.most_recent_instance.message 
          : alert.most_recent_instance?.message?.text || 'No description available'
      }));

      const response = formatCodeQLAlerts(mappedAlerts);
      
      return c.text(
        createAckEvent() +
        createTextEvent(response) +
        createDoneEvent()
      );
    } catch (error) {
      return c.text(
        createErrorsEvent([
          {
            type: "agent",
            message: "Error fetching CodeQL alerts: " + (error instanceof Error ? error.message : String(error)),
            code: "GITHUB_API_ERROR",
            identifier: "github_api_error",
          },
        ])
      );
    }
  }

  // Check if the prompt is asking for CodeQL fix suggestions
  if (userPrompt.toLowerCase().includes("fix codeql") || userPrompt.toLowerCase().includes("fix the vulnerability")) {
    const { owner, repo } = await getRepoInfoFromGitConfig();
    
    try {
      const { data: alerts } = await octokit.request('GET /repos/{owner}/{repo}/code-scanning/alerts', {
        owner,
        repo,
        headers: {
          'X-GitHub-Api-Version': '2022-11-28'
        }
      });

      const mappedAlerts: CodeQLAlert[] = alerts.map(alert => ({
        ...alert,
        title: alert.rule?.description || 'Unknown',
        severity: alert.rule?.security_severity_level || 'unknown',
        description: typeof alert.most_recent_instance?.message === 'string' 
          ? alert.most_recent_instance.message 
          : alert.most_recent_instance?.message?.text || 'No description available'
      }));

      let targetAlert: CodeQLAlert | undefined;
      
      if (userPrompt.toLowerCase().includes("fix the vulnerability")) {
        const vulnIdentifier = userPrompt.match(/"([^"]+)"/)?.[1] || "";
        targetAlert = mappedAlerts.find(alert => {
          const location = alert.most_recent_instance?.location;
          if (!location) return false;
          
          const locationStr = `${location.path}:${location.start_line}`;
          return vulnIdentifier.includes(locationStr);
        });
      } else {
        // If just "fix codeql", take the most severe open alert
        targetAlert = mappedAlerts.find(alert => 
          alert.state === "open" && 
          (alert.severity === "critical" || alert.severity === "high")
        );
      }

      if (!targetAlert) {
        return c.text(
          createErrorsEvent([
            {
              type: "agent",
              message: "No matching vulnerability found.",
              code: "VULN_NOT_FOUND",
              identifier: "vuln_not_found",
            },
          ])
        );
      }

      const fixSuggestion = await generateCodeQLFix(targetAlert, tokenForUser);
      
      return c.text(
        createAckEvent() +
        createTextEvent(fixSuggestion) +
        createDoneEvent()
      );
    } catch (error) {
      return c.text(
        createErrorsEvent([
          {
            type: "agent",
            message: "Error processing CodeQL fix: " + (error instanceof Error ? error.message : String(error)),
            code: "GITHUB_API_ERROR",
            identifier: "github_api_error",
          },
        ])
      );
    }
  }

  // Add new condition for expand command
  if (userPrompt.toLowerCase().startsWith("expand")) {
    const { owner, repo } = await getRepoInfoFromGitConfig();
    const severityLevel = userPrompt.toLowerCase().split(" ")[1];
    
    try {
      const { data: alerts } = await octokit.request('GET /repos/{owner}/{repo}/code-scanning/alerts', {
        owner,
        repo,
        headers: {
          'X-GitHub-Api-Version': '2022-11-28'
        }
      });

      const mappedAlerts: CodeQLAlert[] = alerts.map(alert => ({
        ...alert,
        title: alert.rule?.description || 'Unknown',
        severity: alert.rule?.security_severity_level || 'unknown',
        description: typeof alert.most_recent_instance?.message === 'string' 
          ? alert.most_recent_instance.message 
          : alert.most_recent_instance?.message?.text || 'No description available'
      }));

      // Filter alerts by severity level
      const filteredAlerts = mappedAlerts.filter(alert => 
        alert.severity.toLowerCase() === severityLevel.toLowerCase()
      );

      if (filteredAlerts.length === 0) {
        return c.text(
          createAckEvent() +
          createTextEvent(`No ${severityLevel} severity vulnerabilities found.`) +
          createDoneEvent()
        );
      }

      let response = `# ${severityLevel.charAt(0).toUpperCase() + severityLevel.slice(1)} Severity Vulnerabilities\n\n`;
      response += `| Severity | Title | Location | Fix Command |\n`;
      response += `|:--------:|:------:|:--------:|:----------|\n`;

      filteredAlerts.forEach(alert => {
        const location = alert.most_recent_instance?.location;
        const locationStr = location ? `${location.path}:${location.start_line}` : 'N/A';
        const uniqueId = `${alert.title} in ${locationStr}`;
        
        response += `| **${alert.severity[0].toUpperCase()}** | ${alert.title} | ${locationStr} | \`fix the vulnerability "${uniqueId}"\` |\n`;
      });

      return c.text(
        createAckEvent() +
        createTextEvent(response) +
        createDoneEvent()
      );

    } catch (error) {
      return c.text(
        createErrorsEvent([
          {
            type: "agent",
            message: "Error fetching CodeQL alerts: " + (error instanceof Error ? error.message : String(error)),
            code: "GITHUB_API_ERROR",
            identifier: "github_api_error",
          },
        ])
      );
    }
  }

  // If not asking for vulnerability analysis or Dependabot alerts, return the original response
  return c.text(
    createAckEvent() +
      createTextEvent(
        `Welcome ${user.data.login}! It looks like you asked the following question, "${userPrompt}". This is a GitHub Copilot extension template, so it's up to you to decide what you want to implement to answer prompts.`
      ) +
      createDoneEvent()
  );
});

const port = 3000;
console.log(`Server is running on port ${port}`);

serve({
  fetch: app.fetch,
  port,
});
