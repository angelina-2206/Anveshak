import { ExtractedEmail, AnalysisVerdict, TraceLinkResult } from '../types/investigation';

export const LOCAL_API_BASE = 'http://localhost:8000/api/v1';
export const PROD_API_BASE = 'https://anveshak-xi.vercel.app/api/v1';

export const LOCAL_WEB_BASE = 'http://localhost:5173';
export const PROD_WEB_BASE = 'https://anveshak-xi.vercel.app';

export async function checkLocalhostRunning(): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 800);
    const res = await fetch('http://localhost:8000/health', { method: 'GET', signal: controller.signal });
    clearTimeout(timeoutId);
    if (res.ok) return true;
  } catch {
    // If backend port 8000 isn't running, check dev server port 5173
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 800);
      await fetch('http://localhost:5173', { method: 'HEAD', mode: 'no-cors', signal: controller.signal });
      clearTimeout(timeoutId);
      return true;
    } catch {
      return false;
    }
  }
  return false;
}

export async function getDashboardBaseUrl(): Promise<string> {
  const isLocal = await checkLocalhostRunning();
  return isLocal ? LOCAL_WEB_BASE : PROD_WEB_BASE;
}

export class TraceXClient {
  private apiBase: string;

  constructor(apiBase = LOCAL_API_BASE) {
    this.apiBase = apiBase;
  }

  private async getWorkingApiBases(): Promise<string[]> {
    const isLocal = await checkLocalhostRunning();
    if (isLocal) {
      return [LOCAL_API_BASE, PROD_API_BASE];
    } else {
      return [PROD_API_BASE, LOCAL_API_BASE];
    }
  }

  async analyzeEmail(email: ExtractedEmail): Promise<AnalysisVerdict> {
    const bases = await this.getWorkingApiBases();
    let lastError: Error | null = null;

    for (const base of bases) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 12000); // 12s timeout

      try {
        const response = await fetch(`${base}/extension/analyze`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            source: email.source,
            sender: email.sender,
            recipients: email.recipients,
            subject: email.subject,
            timestamp: email.timestamp,
            body_text: email.bodyText,
            raw_headers: email.rawHeaders,
            urls: email.urls,
            message_id: email.messageId,
          }),
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
          if (response.status === 429) {
            throw new Error('Rate limit exceeded. Please wait a moment before analyzing again.');
          }
          throw new Error(`Server returned error status (${response.status})`);
        }

        const data = await response.json();
        return data as AnalysisVerdict;
      } catch (err: any) {
        clearTimeout(timeoutId);
        if (err.name === 'AbortError') {
          lastError = new Error('Analysis timed out. Anveshak investigation engine did not respond in time.');
        } else {
          lastError = err;
        }
      }
    }

    throw lastError || new Error('Unable to connect to Anveshak forensic backend.');
  }

  async traceLink(url: string): Promise<TraceLinkResult> {
    const bases = await this.getWorkingApiBases();
    let lastError: Error | null = null;

    for (const base of bases) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000);

      try {
        const response = await fetch(`${base}/extension/trace-link`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ url }),
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
          throw new Error(`Link trace failed (${response.status})`);
        }

        return (await response.json()) as TraceLinkResult;
      } catch (err: any) {
        clearTimeout(timeoutId);
        lastError = err;
      }
    }

    throw lastError || new Error('Failed to analyze URL intelligence.');
  }

  async checkHealth(): Promise<boolean> {
    return checkLocalhostRunning();
  }
}

export const tracexClient = new TraceXClient();

