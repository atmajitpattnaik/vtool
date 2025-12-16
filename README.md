## Vulnerability Analyzer

Automated vulnerability noise reduction and reporting system with a React/Vite frontend and a Node/Express backend.  
The tool ingests OWASP / dependency reports and produces a cleaner, prioritized view of vulnerabilities, plus exportable reports.

---

### Project Structure

- **`vtool/client`**: React + Vite single-page app for uploading reports, viewing analysis, and exporting results.
- **`vtool/server`**: Node/Express API that parses reports, runs analyzers, and generates structured JSON output (optionally using Groq).
- **`vtool/sample-data`**: Example OWASP and package manifest files you can use to test the tool.

Key backend modules:
- **Parsers** (`src/parsers`):  
  - `owaspParser.js`: Parses OWASP-style reports.  
  - `manifestParser.js`: Parses package manifests (e.g., `package.json`).
- **Analyzers** (`src/analyzers`):  
  - `vulnerabilityExtractor.js`: Extracts raw vulnerability data.  
  - `falsePositiveDetector.js`: Identifies likely false positives.  
  - `reachabilityAnalyzer.js`: Estimates whether vulnerabilities are actually reachable in practice.
- **Services** (`src/services`):  
  - `groqService.js`: Integrates with Groq LLM (if configured).  
  - `jsonGenerator.js`: Shapes final JSON output for the client.
- **Routes** (`src/routes/analysis.js`): HTTP endpoints used by the client to upload and analyze reports.

---

### Prerequisites

- **Node.js** 18+ (recommended)
- **npm** 8+ (bundled with recent Node versions)
-  A Groq API key

---

### Installation

From the project root (`vtool` folder’s parent):

```bash
cd vtool

# Install frontend dependencies
cd client
npm install

# Install backend dependencies
cd ../server
npm install
```

---

### Running the Backend (Server)

From `vtool/server`:

```bash
cd vtool/server

# Development mode (watches for changes)
npm run dev

# or production-style run
npm start
```

By default the server will:
- Start an Express app from `src/index.js`.
- Expose analysis routes under something like `/analysis` (see `src/routes/analysis.js` for the exact paths).

#### Environment Configuration

Create a `.env` file in `vtool/server` (if you need Groq or other config):

```bash
GROQ_API_KEY=your_groq_api_key_here       # or any port you prefer
```

Check `src/index.js` and `src/services/groqService.js` for the exact variable names used.

---

### Running the Frontend (Client)

From `vtool/client`:

```bash
cd vtool/client
npm run dev
```

Vite will start a dev server (typically on `http://localhost:5173` by default).

If the backend runs on a different port (for example `http://localhost:5000`), ensure the frontend is configured to call that API base URL (usually via an environment variable or config constant in the client code).


### Using the App

1. **Start the backend** (`npm run dev` in `vtool/server`).
2. **Start the frontend** (`npm run dev` in `vtool/client`).
3. Open the Vite dev URL in your browser (e.g. `http://localhost:5173`).
4. In the UI:
   - Use the **file upload** view to upload OWASP reports and/or package manifests.
   - Trigger analysis; the client sends files to the backend `/analysis` routes.
   - Review the summarized vulnerabilities, false-positive suggestions, and reachability insights.
   - Use **export options** (e.g., PDF via `html2pdf.js`) to download reports.