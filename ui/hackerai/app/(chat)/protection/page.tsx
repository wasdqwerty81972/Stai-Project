import type { Metadata } from "next";

import { canonicalMetadata } from "@/lib/seo/site";
import { SvsProtectionDashboard } from "@/app/components/svs/SvsProtectionDashboard";

export const metadata: Metadata = {
  ...canonicalMetadata("/protection"),
  title: "SVS Cyber - Windows Endpoint Dashboard",
};

export default function Page() {
  return <SvsProtectionDashboard />;
}
