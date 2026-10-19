import type { Metadata } from "next";

import { canonicalMetadata } from "@/lib/seo/site";
import { StaiChatWorkspace } from "../components/StaiChatWorkspace";

export const metadata: Metadata = {
  ...canonicalMetadata("/"),
  title: "SVS-Cyber - Defensive Security AI",
};

export default function Page() {
  return <StaiChatWorkspace landing />;
}
