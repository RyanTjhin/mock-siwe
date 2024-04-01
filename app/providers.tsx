"use client";

import { siweConfig } from "@/config/config";
import { siweClient } from "@/utils/siwe/siweClient";
import {
  ConnectKitProvider,
  SIWEConfig,
  SIWEProvider,
  getDefaultConfig,
} from "connectkit";
import { Oxanium } from "next/font/google";
import * as React from "react";
import { SiweMessage } from "siwe";
import { WagmiConfig, configureChains, createConfig, mainnet } from "wagmi";
import { publicProvider } from "wagmi/providers/public";

const oxanium = Oxanium({ subsets: ["latin"] });

const { chains, publicClient, webSocketPublicClient } = configureChains(
  [mainnet],
  [publicProvider()],
  { pollingInterval: 25_000 } // 25s
);

const config = createConfig(
  getDefaultConfig({
    // Required API Keys
    alchemyId: process.env.ALCHEMY_ID, // or infuraId
    walletConnectProjectId: process.env.WALLETCONNECT_PROJECT_ID ?? "",
    // Required
    appName: "Any Ape",
    // Optional
    appDescription: "Any Ape",
    chains,
    publicClient,
    webSocketPublicClient,
  })
);

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <WagmiConfig config={config}>
      <SIWEProvider {...siweConfig}>
        <ConnectKitProvider>{children}</ConnectKitProvider>
      </SIWEProvider>
    </WagmiConfig>
  );
}
