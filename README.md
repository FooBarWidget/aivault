# DrivePlug: long-term memory for AI agents through Google Drive

DrivePlug lets AI agents store long-term memory in Google Drive, allowing them to learn and plan. It's an API that agents can use to read from and write to a Google Drive folder.

What sets our approach apart from other solutions:

- **Simple design**

  We assume that:

  - You're using an LLM with a large context window (let's say GPT-4o with 128k window, or Claude 3.5 Sonnet with 200k window).
  - Documents are small enough to comfortably fit in the context window.

  With these assumptions, we can avoid a lot of the complexity and overhead that comes with more sophisticated approaches to AI memory management. For example, we can avoid the use of vector databases, embeddings, chunking, etc.

- **Observable and adjustable**

  Because memory is stored in Google Drive, any human who has access to the Google Drive folder can easily check what the memory contents are, and adjust them if necessary.

- **Designed for hosted AI agent platforms such as OpenAI Custom GPTs**

  DrivePlug is specifically designed to address the security and compliance challenges that come from using hosted AI agent platforms such as OpenAI Custom GPTs, although it works fine with other agent platforms as well.

- **Secure**

  Other solutions to connect AI agents to Google Drive tend to grant full access to Google Drive. Not only the agent gets that access, but the AI hosting provider (such as OpenAI) as well. All this violates the security best practice of "least privilege".

  DrivePlug only allows access to a specific Google Drive folder.

- **Simple access control**

  When using OpenAI Custom GPTs, it's hard to control who can access the agent (and indirectly, its memory as well). DrivePlug gets its Google Drive credentials from the user. This makes access control very easy: the only people who can effectively use the agent, are the people who have access to the Google Drive folder in which the agent stores memory.

- **Compliant**

  DrivePlug is a self-hosted application. Your data doesn't have to be processed by yet another third party, making it easier to be compliant with privacy laws.

- **Easy to deploy and operate**

  DrivePlug has a stateless design, which means that it does not require a database. This makes it very easy to deploy and to operate, with fewer things that can go wrong.

## Approach

The approach towards using DrivePlug is that:

- Agents decide, through a list of filenames, what documents to read to write.
- Agents read and write entire documents, not parts of them. There is one exception: the main memory.

### Main memory

The main memory is the core of what the agent has learned or is planning. This document is a bit different from other files in Google Drive: it's an append-only document. When agents write to memory, a new entry is added, so that we can check how the memory has changed over time. Agents can only read the latest revision of the memory.

DrivePlug provides a special API for this pattern so that they can never falsify their memory history.
