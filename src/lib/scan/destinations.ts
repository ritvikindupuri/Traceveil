export const MCP_DESTINATIONS = [
  {name:'DeepWiki',endpoint:'https://mcp.deepwiki.com/mcp',auth:true,tools:['read_wiki_structure','read_wiki_contents','ask_question']},
  {name:'Cloudflare Docs',endpoint:'https://docs.mcp.cloudflare.com/mcp',auth:false,tools:['search_cloudflare_documentation','migrate_pages_to_workers_guide']},
  {name:'Microsoft Learn',endpoint:'https://learn.microsoft.com/api/mcp',auth:false,tools:['microsoft_docs_search','microsoft_code_sample_search']},
] as const;

export function trustedDestination(endpoint:string) {
  const url = new URL(endpoint);
  if (url.username || url.password || url.hash || url.search) return undefined;
  return MCP_DESTINATIONS.find(d => d.endpoint === url.href);
}