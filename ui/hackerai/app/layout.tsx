import type { Metadata } from "next";
import { headers } from "next/headers";
import { Geist, Geist_Mono } from "next/font/google";
import { withAuth as getAuthFromWorkOS } from "@workos-inc/authkit-nextjs";
import "./globals.css";

import { ConvexClientProvider } from "@/components/ConvexClientProvider";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Toaster } from "@/components/ui/sonner";
import { resolveClientInitialAuth } from "@/lib/auth/initial-auth";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "SVS-Cyber",
  description: "Defensive security investigation assistant",
  manifest: "/manifest.json",
};

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const requestHeaders = await headers();
  const withAuth = async () => {
    if (!requestHeaders.has("x-workos-middleware")) return { user: null };
    return getAuthFromWorkOS();
  };
  const initialAuth = await resolveClientInitialAuth(withAuth);

  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} dark h-full`}
      suppressHydrationWarning
    >
      <head>
        <meta
          name="viewport"
          content="width=device-width, initial-scale=1, viewport-fit=cover"
        />
        <meta
          name="stai-backend-origin"
          content={process.env.STAI_API_ORIGIN || "http://127.0.0.1:6764"}
        />
        <link rel="apple-touch-icon" href="/apple-touch-icon.png" />
      </head>
      <body className="antialiased h-full">
        <ConvexClientProvider initialAuth={initialAuth}>
          <TooltipProvider>
            {children}
            <Toaster />
          </TooltipProvider>
        </ConvexClientProvider>
      </body>
    </html>
  );
}
