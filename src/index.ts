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
        token: token,
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
    const repoUrl = userPrompt.match(/https:\/\/github\.com\/([^\/]+)\/([^\/]+)/);
    
    if (repoUrl) {
      const [, owner, repo] = repoUrl;
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

  // Add new function to get remediation steps
  async function getRemediationSteps(issues: any, token: string) {
    const remediationPrompt = `Please provide step-by-step remediation instructions for the following vulnerabilities:
    
${issues.data.attributes.title} (${issues.data.attributes.effective_severity_level}):
${issues.data.attributes.description} ${issues.data.attributes.resolution.details}

${issues.included[0].attributes.title} (${issues.included[0].attributes.effective_severity_level}):
${issues.included[0].attributes.description} ${issues.included[0].attributes.resolution.details}

Please format the response with clear steps and include the suggested package upgrades.`;

    try {
      const { message } = await prompt(remediationPrompt, {
        model: "gpt-4",
        token: token,
        
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
