# Security Analysis Copilot Extension

A GitHub Copilot extension that helps developers identify and fix security vulnerabilities in their code. This extension integrates with CodeQL, Snyk, and Dependabot to provide comprehensive security analysis.

## Available Commands

### CodeQL Commands

- `list codeql` - Shows a summary of all CodeQL security alerts, grouped by severity
- `expand {severity}` - Lists all vulnerabilities of a specific severity level
  - Example: `expand medium`, `expand high`, `expand critical`, `expand low`
- `fix the vulnerability "{location}"` - Get detailed fix suggestions for a specific vulnerability
  - Example: `fix the vulnerability "Hard-coded credentials in vulnerable/vulnerable1.ts:12"`
- `fix codeql` - Get fix suggestions for the most severe open alert

### Snyk Commands

- `snyk` - Shows a summary of all Snyk security vulnerabilities in your project
- `fix vuln` - Get detailed remediation steps for Snyk vulnerabilities

### Dependabot Commands

- `dependabot alerts` - Lists all Dependabot security alerts for your repository

### Code Analysis Commands

- `vulnerabilities {code}` - Analyzes provided code snippet for potential security vulnerabilities
  - Example: `vulnerabilities function login(password) { ... }`

## Response Format

### Vulnerability Summaries
Vulnerabilities are typically displayed in a table format with the following columns:
- Severity (C = Critical, H = High, M = Medium, L = Low)
- Title
- Location (file path and line number)
- Fix Command

### Fix Suggestions
When requesting fixes, you'll receive:
1. Explanation of the vulnerability
2. Specific code fixes with before/after comparisons
3. Additional security best practices
4. Testing recommendations

## Notes

- The extension requires appropriate GitHub tokens and permissions to access security features
- Fix suggestions are generated using GPT-4 and should be reviewed before implementation
- Some commands may require specific security tools to be enabled in your repository

## Development

Start the server
```
npm install
npm run dev
```

Open the extension
```
open http://localhost:3000
```
