#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { TOOL_DEFINITIONS, executeTool } from './tools/index.js';
import { getGuardrails, renderGuardrailsMarkdown } from './guardrails/generator.js';

const server = new Server(
  {
    name: 'shield-security',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
      resources: {},
      prompts: {},
    },
  }
);

// List tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: TOOL_DEFINITIONS.map(t => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
    })),
  };
});

// Call tools
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  return executeTool(name, (args || {}) as Record<string, string>);
});

// Resources
server.setRequestHandler(ListResourcesRequestSchema, async () => {
  return {
    resources: [
      {
        uri: 'shield://project/security-context',
        name: 'Current Security Posture',
        description: 'Overview of the current project security context and recent findings',
        mimeType: 'application/json',
      },
      {
        uri: 'shield://guardrails/active',
        name: 'Active Security Guardrails',
        description: 'Current security guardrails for this project',
        mimeType: 'text/markdown',
      },
      {
        uri: 'shield://guardrails/nextjs',
        name: 'Next.js Security Guardrails',
        description: 'Security guardrails for Next.js projects',
        mimeType: 'text/markdown',
      },
      {
        uri: 'shield://guardrails/express',
        name: 'Express.js Security Guardrails',
        description: 'Security guardrails for Express.js projects',
        mimeType: 'text/markdown',
      },
    ],
  };
});

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const { uri } = request.params;

  if (uri === 'shield://project/security-context') {
    const context = {
      platform: 'SHIELD Security Platform',
      version: '1.0.0',
      status: 'active',
      capabilities: [
        'SAST scanning (AST-based)',
        'SCA with OSV database integration',
        'Secrets detection with 18+ patterns',
        'IaC security analysis',
        'Intelligent triage with noise reduction',
        'Priority scoring (0-100)',
        'AI guardrails generation',
      ],
      lastScan: null,
      note: 'Run shield_scan_project to get current security posture',
    };

    return {
      contents: [{
        uri,
        mimeType: 'application/json',
        text: JSON.stringify(context, null, 2),
      }],
    };
  }

  if (uri === 'shield://guardrails/active') {
    const guardrails = getGuardrails('generic');
    return {
      contents: [{
        uri,
        mimeType: 'text/markdown',
        text: renderGuardrailsMarkdown(guardrails),
      }],
    };
  }

  if (uri === 'shield://guardrails/nextjs') {
    const guardrails = getGuardrails('nextjs');
    return {
      contents: [{
        uri,
        mimeType: 'text/markdown',
        text: renderGuardrailsMarkdown(guardrails),
      }],
    };
  }

  if (uri === 'shield://guardrails/express') {
    const guardrails = getGuardrails('express');
    return {
      contents: [{
        uri,
        mimeType: 'text/markdown',
        text: renderGuardrailsMarkdown(guardrails),
      }],
    };
  }

  throw new Error(`Unknown resource: ${uri}`);
});

// Prompts
server.setRequestHandler(ListPromptsRequestSchema, async () => {
  return {
    prompts: [
      {
        name: 'secure_code_review',
        description: 'Review code for security vulnerabilities and suggest fixes',
        arguments: [
          { name: 'code', description: 'The code to review', required: true },
          { name: 'language', description: 'Programming language', required: false },
          { name: 'framework', description: 'Framework being used', required: false },
        ],
      },
      {
        name: 'secure_api_endpoint',
        description: 'Generate a secure API endpoint with proper auth, validation, and error handling',
        arguments: [
          { name: 'framework', description: 'Framework (nextjs/express/fastapi)', required: true },
          { name: 'purpose', description: 'What the endpoint should do', required: true },
          { name: 'method', description: 'HTTP method (GET/POST/PUT/DELETE)', required: false },
        ],
      },
    ],
  };
});

server.setRequestHandler(GetPromptRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const promptArgs = (args || {}) as Record<string, string>;

  if (name === 'secure_code_review') {
    const code = promptArgs.code || '[paste code here]';
    const language = promptArgs.language || 'TypeScript';
    const framework = promptArgs.framework || 'unknown';

    return {
      messages: [
        {
          role: 'user',
          content: {
            type: 'text',
            text: `You are a security expert. Review the following ${language} code${framework !== 'unknown' ? ` (using ${framework})` : ''} for security vulnerabilities.

Focus on:
1. Injection vulnerabilities (SQL, NoSQL, command, LDAP)
2. Authentication and authorization issues (missing auth, IDOR)
3. Sensitive data exposure (hardcoded secrets, logging PII)
4. XSS and content injection
5. Path traversal and file inclusion
6. Insecure deserialization
7. Security misconfiguration

For each finding:
- Describe the vulnerability
- Reference the CWE number
- Show the vulnerable code snippet
- Provide a fixed version of the code
- Explain why the fix works

Code to review:
\`\`\`${language.toLowerCase()}
${code}
\`\`\``,
          },
        },
      ],
    };
  }

  if (name === 'secure_api_endpoint') {
    const framework = promptArgs.framework || 'nextjs';
    const purpose = promptArgs.purpose || 'generic CRUD operation';
    const method = promptArgs.method || 'POST';

    return {
      messages: [
        {
          role: 'user',
          content: {
            type: 'text',
            text: `Generate a secure ${method} API endpoint using ${framework} that handles: ${purpose}

Requirements:
1. Authentication check (session/JWT validation)
2. Input validation using Zod or similar schema validation
3. Rate limiting on sensitive operations
4. Proper error handling (no stack traces in responses)
5. Ownership verification for resource access (prevent IDOR)
6. SQL/NoSQL injection prevention
7. Appropriate HTTP status codes
8. Security-relevant logging (without logging sensitive data)

Include comments explaining each security decision. The code should be production-ready.`,
          },
        },
      ],
    };
  }

  throw new Error(`Unknown prompt: ${name}`);
});

export async function startMCPServer(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('SHIELD MCP Server running on stdio');
}

// Auto-start if run directly
startMCPServer().catch((err) => {
  console.error('MCP Server error:', err);
  process.exit(1);
});
