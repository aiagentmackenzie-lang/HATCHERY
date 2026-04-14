import type { StaticResults } from '../App'

interface Props {
  staticResults: StaticResults | null
}

export default function YARAResults({ staticResults }: Props) {
  if (!staticResults) {
    return <div className="flex items-center justify-center h-32 text-[#4a4a5a] text-sm">No static analysis results yet</div>
  }

  const yara = safeParse(staticResults.yara_json)
  const capa = safeParse(staticResults.capa_json)
  const packer = safeParse(staticResults.packer_json)
  const mitre = safeParse(staticResults.mitre_json)
  const pe = safeParse(staticResults.pe_json)
  const strings = safeParse(staticResults.strings_json)

  return (
    <div className="space-y-6">
      {/* YARA matches */}
      <section>
        <h3 className="text-sm font-bold text-[#ff6b35] mb-3 uppercase tracking-wider">YARA Matches</h3>
        {yara?.matches?.length ? (
          <div className="space-y-2">
            {yara.matches.map((m: any, i: number) => (
              <div key={i} className="bg-[#13131a] rounded border border-[#2a2a3a] p-3">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-bold text-[#ff3366]">{m.rule}</span>
                  <span className="text-xs text-[#6a6a7a]">{m.namespace}</span>
                </div>
                {m.meta?.description && (
                  <p className="text-xs text-[#e0e0e0]">{m.meta.description}</p>
                )}
                {m.meta?.mitre_attck && (
                  <p className="text-xs text-[#ffaa00] mt-1">MITRE: {m.meta.mitre_attck}</p>
                )}
                {m.tags?.length > 0 && (
                  <div className="flex gap-1 mt-1.5">
                    {m.tags.map((tag: string) => (
                      <span key={tag} className="px-1.5 py-0.5 bg-[#1a1a24] rounded text-[10px] text-[#6a6a7a]">{tag}</span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-[#4a4a5a]">No YARA rule matches</p>
        )}
      </section>

      {/* capa capabilities */}
      <section>
        <h3 className="text-sm font-bold text-[#00aaff] mb-3 uppercase tracking-wider">Capabilities (capa)</h3>
        {capa?.capabilities?.length ? (
          <div className="space-y-2">
            {capa.capabilities.map((cap: any, i: number) => (
              <div key={i} className="bg-[#13131a] rounded border border-[#2a2a3a] p-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-[#ff6b35] font-bold">{cap.name}</span>
                  <span className="text-xs text-[#6a6a7a]">{cap.namespace}</span>
                </div>
                {cap.attack_techniques?.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-1.5">
                    {cap.attack_techniques.map((t: any) => (
                      <span key={t.id} className="px-1.5 py-0.5 bg-[#ffaa00]/10 border border-[#ffaa00]/30 rounded text-[10px] text-[#ffaa00]">
                        {t.id} {t.technique}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-[#4a4a5a]">{capa?.is_available === false ? 'capa not available (install with: pip install flare-capa)' : 'No capabilities detected'}</p>
        )}
      </section>

      {/* Packer detection */}
      <section>
        <h3 className="text-sm font-bold text-[#ffaa00] mb-3 uppercase tracking-wider">Packer Detection</h3>
        {packer?.packers?.length ? (
          <div className="space-y-2">
            {packer.packers.map((p: any, i: number) => (
              <div key={i} className="bg-[#13131a] rounded border border-[#2a2a3a] p-3">
                <span className="text-sm text-[#ff6b35] font-bold">{p.name}</span>
                <span className="text-xs text-[#6a6a7a] ml-2">confidence: {p.confidence}</span>
                {p.indicators?.length > 0 && (
                  <div className="text-xs text-[#4a4a5a] mt-1">
                    Indicators: {p.indicators.join(', ')}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-[#4a4a5a]">{packer?.is_packed ? 'Packed (no specific packer identified)' : 'No packers detected'}</p>
        )}
      </section>

      {/* MITRE ATT&CK */}
      {mitre?.techniques?.length > 0 && (
        <section>
          <h3 className="text-sm font-bold text-[#ff3366] mb-3 uppercase tracking-wider">MITRE ATT&CK</h3>
          <div className="grid grid-cols-2 gap-2">
            {mitre.techniques.map((t: any, i: number) => (
              <div key={i} className="bg-[#13131a] rounded border border-[#2a2a3a] p-2.5">
                <div className="text-xs text-[#ffaa00] font-bold">{t.technique_id}</div>
                <div className="text-xs text-[#e0e0e0]">{t.technique_name}</div>
                <div className="text-[10px] text-[#6a6a7a] mt-0.5">{t.tactic} · {t.source}</div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* PE analysis (if available) */}
      {pe?.is_valid_pe && (
        <section>
          <h3 className="text-sm font-bold text-[#00ff9f] mb-3 uppercase tracking-wider">PE Analysis</h3>
          <div className="bg-[#13131a] rounded border border-[#2a2a3a] p-3 grid grid-cols-2 gap-2 text-xs">
            <div><span className="text-[#6a6a7a]">Machine:</span> <span className="text-[#e0e0e0]">{pe.machine_type}</span></div>
            <div><span className="text-[#6a6a7a]">Subsystem:</span> <span className="text-[#e0e0e0]">{pe.subsystem}</span></div>
            <div><span className="text-[#6a6a7a]">Sections:</span> <span className="text-[#e0e0e0]">{pe.sections?.length}</span></div>
            <div><span className="text-[#6a6a7a]">Imports:</span> <span className="text-[#e0e0e0]">{pe.imports?.length}</span></div>
            <div><span className="text-[#6a6a7a]">Compiled:</span> <span className="text-[#e0e0e0]">{pe.compile_timestamp}</span></div>
            {pe.suspicious_indicators?.length > 0 && (
              <div className="col-span-2"><span className="text-[#ff3366]">⚠ Suspicious:</span> <span className="text-[#e0e0e0]">{pe.suspicious_indicators.join(', ')}</span></div>
            )}
          </div>
        </section>
      )}

      {/* Strings summary */}
      {strings && (
        <section>
          <h3 className="text-sm font-bold text-[#6a6a7a] mb-3 uppercase tracking-wider">Strings Summary</h3>
          <div className="bg-[#13131a] rounded border border-[#2a2a3a] p-3 grid grid-cols-5 gap-2 text-xs text-center">
            <div><div className="text-lg font-bold text-[#e0e0e0]">{strings.urls?.length ?? 0}</div><div className="text-[#6a6a7a]">URLs</div></div>
            <div><div className="text-lg font-bold text-[#e0e0e0]">{strings.ips?.length ?? 0}</div><div className="text-[#6a6a7a]">IPs</div></div>
            <div><div className="text-lg font-bold text-[#e0e0e0]">{strings.domains?.length ?? 0}</div><div className="text-[#6a6a7a]">Domains</div></div>
            <div><div className="text-lg font-bold text-[#e0e0e0]">{strings.emails?.length ?? 0}</div><div className="text-[#6a6a7a]">Emails</div></div>
            <div><div className="text-lg font-bold text-[#e0e0e0]">{strings.registry_keys?.length ?? 0}</div><div className="text-[#6a6a7a]">RegKeys</div></div>
          </div>
        </section>
      )}
    </div>
  )
}

function safeParse(json: string | null | undefined): any {
  if (!json) return null
  try { return JSON.parse(json) } catch { return null }
}