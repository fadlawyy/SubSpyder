# Module 3: AI-Powered Subdomain Prediction (`SubSpyder` Project)

## Goal

Module 3 uses **Google's Gemini AI model** to predict additional subdomains based on the identity of a website (e.g. technical, e-commerce, etc.).

It extends the output from earlier enumeration modules by generating *intelligent guesses* based on known patterns and web architecture.

---

## 🔍 How It Works

### 1. Input

- **Domain name** (e.g. `kareem.net`)
- **Known subdomains** (from Module 2)
  - e.g., `["www.kareem.net", "api.kareem.net", "blog.kareem.net"]`

---

### 2. Detect Website Type

Using a simple classifier based on keyword matching, we categorize the domain into types like:

- `technical`
- `ecommerce`
- `news`
- `blog`
- `generic`

This helps the AI understand the context of the website before generating predictions.

---

### 3. Prompt Gemini AI

We craft a **structured prompt** with this format:

```text
Given the domain 'kareem.net' and its known subdomains ['www.kareem.net', 'api.kareem.net', 'blog.kareem.net'],
predict possible additional subdomains that might exist for a technical website.
Respond ONLY in this JSON format:
{
  "intelligence": [
    "sub1.kareem.net",
    "sub2.kareem.net"
  ]
}
