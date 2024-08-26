# AI Memory Gateway

AI Memory Gateway provides secure, controlled memory storage for AI agents, such as Custom GPT. AI agents are more effective when they have storage space to store memory and working documents. At the same time, they should not have access to data which they have no need for.

AI Memory Gateway provides an API that allows AI agents to access only specific Google Drive folders, thus achieving data compartmentalization and security. Furthermore, it uses the user's Google account for authentication.

Key features include:

- Secure API for CRUD operations on an administrator-designated Google Drive folder.
- Stateless architecture using encrypted OAuth2 tokens.
