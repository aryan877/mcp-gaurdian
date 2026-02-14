import type { Metadata } from "next";
import { Space_Mono } from "next/font/google";
import "./globals.css";
import { Sidebar } from "@/components/sidebar";
import { TooltipProvider } from "@/components/ui/tooltip";

const spaceMono = Space_Mono({
  weight: ["400", "700"],
  subsets: ["latin"],
  variable: "--font-space-mono",
});

export const metadata: Metadata = {
  title: "MCP Guardian | Security Auditor for Archestra",
  description:
    "AI-powered security auditor for MCP servers. Scan, test, and enforce security policies on the Archestra platform.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className={`${spaceMono.variable} font-mono antialiased`}>
        <TooltipProvider>
          <div className="flex min-h-screen">
            <Sidebar />
            <main className="flex-1 ml-[260px]">{children}</main>
          </div>
        </TooltipProvider>
      </body>
    </html>
  );
}
