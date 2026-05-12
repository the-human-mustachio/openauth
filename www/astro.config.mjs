import theme from "toolbeam-docs-theme"
import starlight from "@astrojs/starlight"
import { defineConfig } from "astro/config"
import { rehypeHeadingIds } from "@astrojs/markdown-remark"
import rehypeAutolinkHeadings from "rehype-autolink-headings"
import config from "./config"

const url = "https://openauth.js.org"

// https://astro.build/config
export default defineConfig({
  site: url,
  trailingSlash: 'always',
  devToolbar: {
    enabled: false,
  },
  integrations: [
    starlight({
      plugins: [theme()],
      title: "OpenAuth",
      description: "Universal, standards-based auth provider.",
      head: [
        {
          tag: "link",
          attrs: {
            rel: "icon",
            href: "/favicon.ico",
            sizes: "48x48",
          },
        },
        // Add light/dark mode favicon
        {
          tag: "link",
          attrs: {
            rel: "icon",
            href: "/favicon.svg",
            media: "(prefers-color-scheme: light)",
          },
        },
        {
          tag: "link",
          attrs: {
            rel: "icon",
            href: "/favicon-dark.svg",
            media: "(prefers-color-scheme: dark)",
          },
        },
        {
          tag: "meta",
          attrs: {
            property: "og:image",
            content: `${url}/social-share.png`,
          },
        },
        {
          tag: "meta",
          attrs: {
            property: "twitter:image",
            content: `${url}/social-share.png`,
          },
        },
      ],
      logo: {
        light: "./src/assets/logo-light.svg",
        dark: "./src/assets/logo-dark.svg",
        replacesTitle: true,
      },
      social: {
        github: config.github,
        discord: config.discord,
      },
      lastUpdated: true,
      editLink: {
        baseUrl: `${config.github}/edit/master/www/`,
      },
      components: {
        Hero: "./src/components/Hero.astro",
      },
      customCss: [
        "./src/custom.css",
        "./src/styles/lander.css",
      ],
      sidebar: [
        { label: "Intro", slug: "docs" },
        { label: "Getting started", slug: "docs/getting-started" },
        {
          label: "Concepts",
          items: [
            { label: "Embedding pattern", slug: "docs/concepts/embedding" },
            { label: "Tenants", slug: "docs/concepts/tenants" },
            { label: "Methods", slug: "docs/concepts/methods" },
            { label: "Flow lifecycle", slug: "docs/concepts/flow" },
            { label: "Standards & hardening", slug: "docs/concepts/standards" },
          ],
        },
        {
          label: "Reference",
          items: [
            { label: "createIdP", slug: "docs/reference/idp" },
            { label: "Built-in methods", slug: "docs/reference/methods" },
            { label: "OAuth/OIDC providers", slug: "docs/reference/providers" },
            { label: "Storage adapters", slug: "docs/reference/adapters" },
            { label: "Subjects", slug: "docs/reference/subjects" },
            { label: "Client", slug: "docs/reference/client" },
          ],
        },
      ],
    }),
  ],
  markdown: {
    rehypePlugins: [
      rehypeHeadingIds,
      [rehypeAutolinkHeadings, { behavior: "wrap" }],
    ],
  },
})
