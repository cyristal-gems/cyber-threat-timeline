// v9.3: DOMContentLoaded guard; same visuals & layout. Ensures graph + filters render.
document.addEventListener('DOMContentLoaded', () => {
  if (typeof d3 === 'undefined') {
    console.error('D3 failed to load.');
    return;
  }

  const TYPES = ["Ransomware","Data Breach","Zero-day",
  { title:"Michelangelo Virus Outbreak", date:"1992-03-06", industry:"Tech", type:"Zero-day", impact:"Global consumer PC infections on activation date", description:"The Michelangelo DOS virus triggered payloads on March 6, causing data corruption. Media coverage spurred antivirus adoption and better user awareness. Vendors coordinated to distribute removal tools.", sources:["https://en.wikipedia.org/wiki/Michelangelo_(computer_virus)"] },
  { title:"USAF Rome Laboratory Intrusion", date:"1994-03-28", industry:"Gov", type:"Data Breach", impact:"Defense research networks accessed", description:"Attackers routed through overseas systems to penetrate the U.S. Air Force Rome Lab. Investigations traced multiple compromised hosts. The case shaped incident response playbooks for defense networks.", sources:["https://en.wikipedia.org/wiki/Rome_Laboratory#1994_security_breach"] },
  { title:"Kevin Mitnick Pursuit Incidents", date:"1995-12-25", industry:"Tech", type:"Data Breach", impact:"Multiple telecom and software targets", description:"Mitnick\u2019s intrusions included theft of source code and telecom data. The pursuit popularized digital forensics techniques. It raised public awareness of password and network hygiene.", sources:["https://en.wikipedia.org/wiki/Kevin_Mitnick"] },
  { title:"Omega Engineering Logic Bomb", date:"1996-07-31", industry:"Manufacturing", type:"Data Breach", impact:"Manufacturing data wiped; significant losses", description:"A disgruntled insider planted a logic bomb that deleted critical files. The sabotage disrupted production and led to criminal charges. Insider threat monitoring became a priority for industrial IT.", sources:["https://www.justice.gov/archive/criminal/cybercrime/press-releases/2001/ricciardiIndict.htm"] },
  { title:"CIH/Chernobyl Virus", date:"1998-04-26", industry:"Tech", type:"Zero-day", impact:"Data loss and some BIOS corruption", description:"The CIH virus overwrote disk data and in some cases corrupted BIOS chips. Its timed activation caused widespread damage. Firmware recovery practices gained attention.", sources:["https://en.wikipedia.org/wiki/CIH_(computer_virus)"] },
  { title:"Operation Moonlight Maze", date:"1999-03-01", industry:"Gov", type:"Data Breach", impact:"Long\u2011term exfiltration from U.S. government and research networks", description:"Moonlight Maze involved sustained intrusions and data exfiltration using proxy chains. It revealed the scope of state\u2011linked cyber\u2011espionage. The operation reshaped interagency coordination.", sources:["https://en.wikipedia.org/wiki/Moonlight_Maze"] },
  { title:"Happy99 Worm", date:"1999-01-10", industry:"Tech", type:"Zero-day", impact:"Email\u2011propagating malware across consumer PCs", description:"Happy99 spread via email attachments by displaying fireworks while modifying Winsock. It foreshadowed mass\u2011mailing worm techniques. User education and mail filtering improved as a result.", sources:["https://en.wikipedia.org/wiki/Happy99"] },
  { title:"Melissa Macro Virus", date:"1999-03-26", industry:"Tech", type:"Zero-day", impact:"Email systems overloaded; large enterprises disrupted", description:"Melissa abused Word macros to exfiltrate contacts and mass\u2011mail itself. ISPs throttled mail and enterprises filtered attachments. The outbreak accelerated macro security changes.", sources:["https://en.wikipedia.org/wiki/Melissa_(computer_virus)"] },
  { title:"NASA / DoD Hack by Jonathan James", date:"1999-06-29", industry:"Gov", type:"Data Breach", impact:"NASA source code and DoD network data accessed", description:"A teenager penetrated NASA and DoD systems, prompting temporary shutdowns. The case showcased perimeter gaps and credential hygiene weaknesses. Agencies hardened remote access and monitoring.", sources:["https://en.wikipedia.org/wiki/Jonathan_James"] },
  { title:"Phonemasters Telecom Intrusions", date:"1998-09-01", industry:"Telecom", type:"Data Breach", impact:"Billing systems and customer data at risk", description:"The Phonemasters group illegally accessed telecom systems across providers. They manipulated billing and calling-card data. The investigation strengthened cross\u2011carrier security cooperation.", sources:["https://en.wikipedia.org/wiki/Phonemasters"] }];
  const DATA = [
    // Ransomware (20)
    { title:"CryptoLocker", date:"2013-09-05", industry:"Multiple", type:"Ransomware", impact:"Hundreds of thousands of PCs", description:"CryptoLocker popularized strong public‑key encryption for extortion at scale. It spread via email attachments and botnets, locking user files for Bitcoin payments. Law‑enforcement sinkholes later disrupted infrastructure but copycats proliferated.", sources:["https://www.cisa.gov/news-events/alerts/2014/06/10/us-cert-alert-cryptolocker-ransomware"] },
    { title:"LockerGoga at Norsk Hydro", date:"2019-03-19", industry:"Manufacturing", type:"Ransomware", impact:"Global aluminum operations", description:"Norsk Hydro switched to manual operations after LockerGoga encrypted systems. The firm posted daily updates, earning praise for transparency. Highlighted OT/IT interdependencies in heavy industry.", sources:["https://www.norskhydro.com/media/news/2019/cyber-attack/"] },
    { title:"Baltimore City – RobbinHood", date:"2019-05-07", industry:"Gov", type:"Ransomware", impact:"City services disrupted", description:"Municipal systems were encrypted, disrupting billing and property transactions. Recovery took weeks and cost millions. Pushed governments toward offline backups and segmentation.", sources:["https://www.baltimorecity.gov/news/mayor-news/2019-05-29-statement-ransomware-attack"] },
    { title:"Travelex – Sodinokibi/REvil", date:"2019-12-31", industry:"Finance", type:"Ransomware", impact:"Foreign exchange services offline", description:"Sodinokibi deployed across Travelex around New Year’s Eve. Branches and online services went dark for weeks; negotiations followed. Underscored holiday‑period risk and supplier exposure.", sources:["https://www.bbc.com/news/technology-51018581"] },
    { title:"Garmin – WastedLocker", date:"2020-07-23", industry:"Tech", type:"Ransomware", impact:"Global outage of services", description:"Multi‑day outage affecting fitness sync and aviation services. Reports indicated WastedLocker and negotiations. Showed cross‑consumer/B2B impact.", sources:["https://www.bleepingcomputer.com/news/security/garmin-outage-caused-by-wastedlocker-ransomware-attack/"] },
    { title:"Kia Motors America", date:"2021-02-13", industry:"Automotive", type:"Ransomware", impact:"IT outages and dealer tools", description:"Ransomware disrupted customer portals and dealership systems. Ties to DoppelPaymer/BitPaymer lineage. Auto supply chains reevaluated DMS resilience.", sources:["https://www.krebsonsecurity.com/2021/02/kia-motors-usa-hit-by-ransomware/"] },
    { title:"Colonial Pipeline – DarkSide", date:"2021-05-07", industry:"Energy", type:"Ransomware", impact:"Fuel distribution halted", description:"Ransomware paused operations on the U.S. East Coast pipeline. Panic buying and shortages followed; authorities recovered part of ransom. Brought national attention to critical infrastructure risk.", sources:["https://www.cisa.gov/news-events/alerts/2021/05/11/darkside-ransomware-compromises-colonial-pipeline-company"] },
    { title:"JBS Foods", date:"2021-05-30", industry:"Manufacturing", type:"Ransomware", impact:"Meat processing disruption", description:"Plants shut in several countries; a ransom was paid to expedite restoration. Food supply chains reconsidered single‑point dependencies.", sources:["https://www.justice.gov/opa/pr/jbs-usa-pays-115-million-ransomware-attack-justice-department-seizes-234-million"] },
    { title:"Kaseya VSA – REvil", date:"2021-07-02", industry:"Tech", type:"Ransomware", impact:"MSP supply‑chain blast radius", description:"Kaseya remote management exploited to push ransomware to downstream customers. Thousands of endpoints across hundreds of orgs hit.", sources:["https://www.cisa.gov/news-events/alerts/2021/07/04/kaseya-vsa-supply-chain-ransomware-attack"] },
    { title:"Conti – Irish Health Service Executive", date:"2021-05-14", industry:"Healthcare", type:"Ransomware", impact:"National health IT disruption", description:"Encryption and data exfiltration across Ireland’s HSE. Government refused payment; recovery was lengthy.", sources:["https://www.gov.ie/en/publication/0da60-hse-cyber-attack/"] },
    { title:"Costa Rica – Conti", date:"2022-04-18", industry:"Gov", type:"Ransomware", impact:"National services impacted", description:"Multi‑agency attacks disrupted finance and trade; a state of emergency was declared.", sources:["https://www.reuters.com/world/americas/costa-rica-declares-state-emergency-over-ransomware-attack-2022-05-09/"] },
    { title:"NHS Supplier – Advanced (Adastra)", date:"2022-08-04", industry:"Healthcare", type:"Ransomware", impact:"Urgent care software outage", description:"Ransomware against a key NHS supplier disrupted referrals and 111 services.", sources:["https://www.ncsc.gov.uk/news/statement-on-advanced-cyber-incident"] },
    { title:"Medibank", date:"2022-10-12", industry:"Healthcare", type:"Ransomware", impact:"Data leak of millions", description:"Records were exfiltrated and leaked when payment was refused. Emphasized ‘double‑extortion’ tactics.", sources:["https://www.medibank.com.au/health/public/incident/updates/"] },
    { title:"Royal Mail UK – LockBit", date:"2023-01-10", industry:"Logistics", type:"Ransomware", impact:"International exports disrupted", description:"LockBit impacted Royal Mail dispatch, forcing manual workarounds.", sources:["https://www.royalmail.com/sending/international/cyber-incident"] },
    { title:"MGM Resorts – ALPHV/BlackCat", date:"2023-09-10", industry:"Hospitality", type:"Ransomware", impact:"Hotel/casino systems degraded", description:"Social engineering enabled ransomware disruption of slots, keys, and booking.", sources:["https://www.sec.gov/ixviewer/doc?action=display&source=content&filename=edgar/data/789570/000078957023000089/pressrelease9-19x23.htm"] },
    { title:"Change Healthcare – ALPHV/BlackCat", date:"2024-02-21", industry:"Healthcare", type:"Ransomware", impact:"Nationwide claims outages", description:"Clearinghouse disruption affected pharmacy and billing nationwide.", sources:["https://www.hhs.gov/about/news/2024/03/10/ocr-issues-bulletin-regarding-ransomware-incident-change-healthcare.html"] },
    { title:"CDK Global", date:"2024-06-19", industry:"Automotive", type:"Ransomware", impact:"Dealer management system offline", description:"Thousands of U.S. dealerships reverted to paper during the outage.", sources:["https://www.reuters.com/technology/cdk-says-some-dealer-management-systems-restored-after-cyber-attack-2024-06-23/"] },
    { title:"NCR Aloha POS", date:"2023-04-13", industry:"Retail", type:"Ransomware", impact:"Restaurant POS outage", description:"Aloha POS and back‑office apps were unavailable; operators used manual ticketing.", sources:["https://www.ncr.com/company/blogs/security/aloha-incident-update"] },
    { title:"KP Cyberattack – Extortion/Ransomware", date:"2023-10-05", industry:"Healthcare", type:"Ransomware", impact:"Regional care delays", description:"Scheduling and portals disrupted while critical care continued.", sources:["https://www.hhs.gov/sites/default/files/threat-brief-stopransomware-healthcare.pdf"] },
    { title:"GPCode / GpCoder Emerges", date:"2005-06-01", industry:"Multiple", type:"Ransomware", impact:"Early crypto‑ransom", description:"Among the earliest file‑encrypting trojans; transitioned from scareware to encryption‑based extortion.", sources:["https://en.wikipedia.org/wiki/Gpcode"] },

    // Data Breach (20)
    { title:"AOHell Phishing on AOL", date:"1994-01-15", industry:"Tech", type:"Data Breach", impact:"Early large‑scale phishing", description:"Automated phishing on AOL harvested passwords and cards; set patterns for credential theft.", sources:["https://en.wikipedia.org/wiki/AOHell"] },
    { title:"Citibank SWIFT Heist", date:"1995-06-01", industry:"Finance", type:"Data Breach", impact:"$10M transfer attempt", description:"Dial‑up access and SWIFT creds enabled fraudulent transfers; case reshaped authentication.", sources:["https://en.wikipedia.org/wiki/Vladimir_Levin"] },
    { title:"Solar Sunrise", date:"1998-02-01", industry:"Gov", type:"Data Breach", impact:"US DoD networks", description:"Teenagers exploited Solaris bugs; investigation refined coordination playbooks.", sources:["https://en.wikipedia.org/wiki/Solar_Sunrise"] },
    { title:"CDUniverse Credit Card Leak", date:"1999-12-25", industry:"Retail", type:"Data Breach", impact:"300k cards posted", description:"Cards published after failed extortion; presaged modern leak sites.", sources:["https://en.wikipedia.org/wiki/CDUniverse"] },
    { title:"Windows 2000 Source Leak", date:"2004-02-12", industry:"Tech", type:"Data Breach", impact:"Source code portions leaked", description:"Leak raised exploit‑development concerns; spurred partner access controls.", sources:["https://en.wikipedia.org/wiki/Windows_2000#Source_code_leak"] },
    { title:"ChoicePoint", date:"2005-02-15", industry:"Data Broker", type:"Data Breach", impact:"145k records", description:"Fraudsters posed as businesses to buy dossiers; catalyzed breach notification laws.", sources:["https://en.wikipedia.org/wiki/ChoicePoint"] },
    { title:"TJX POS Breach", date:"2005-12-01", industry:"Retail", type:"Data Breach", impact:"94M cards", description:"Weak wireless security enabled long‑running card theft; drove PCI enforcement.", sources:["https://en.wikipedia.org/wiki/TJX_Companies#Data_breach"] },
    { title:"Yahoo Breach", date:"2013-08-01", industry:"Tech", type:"Data Breach", impact:"3B accounts", description:"Multi‑year intrusion affected all three billion accounts; prompted resets.", sources:["https://www.justice.gov/opa/pr/us-charges-russian-fsb-officers-and-their-criminal-conspirators-hacking-yahoo"] },
    { title:"Target POS", date:"2013-11-27", industry:"Retail", type:"Data Breach", impact:"40M cards", description:"PoS malware captured cards during holidays; vendor credentials abused.", sources:["https://www.ftc.gov/business-guidance/blog/2017/05/lessons-target"] },
    { title:"Sony Pictures", date:"2014-11-24", industry:"Media", type:"Data Breach", impact:"Leaks & destruction", description:"Hack‑and‑leak with geopolitical ties; unreleased films and emails dumped.", sources:["https://www.justice.gov/opa/pr/north-korean-regime-backed-programmer-charged-conspiracy-conduct-multiple-cyber-attacks-and"] },
    { title:"Anthem", date:"2015-02-04", industry:"Healthcare", type:"Data Breach", impact:"78.8M records", description:"Stolen creds and custom malware; drove MFA and monitoring improvements.", sources:["https://oag.ca.gov/ecrime/databreach/report?id=7075"] },
    { title:"U.S. OPM", date:"2015-06-04", industry:"Gov", type:"Data Breach", impact:"21.5M records", description:"Background‑check data and fingerprints exposed; accelerated federal identity modernization.", sources:["https://www.opm.gov/cybersecurity/cybersecurity-incidents/"] },
    { title:"Ashley Madison", date:"2015-07-19", industry:"Tech", type:"Data Breach", impact:"User data leak", description:"Profiles exfiltrated and leaked; raised ethics and privacy debates.", sources:["https://www.ftc.gov/enforcement/cases-proceedings/162-3164/ashley-madison-and-avid-life-media-settlement"] },
    { title:"Uber 2016 (disclosed 2017)", date:"2016-10-01", industry:"Tech", type:"Data Breach", impact:"57M users & drivers", description:"Repo creds enabled access; concealment led to penalties; popularized secret‑management.", sources:["https://www.ftc.gov/news-events/news/press-releases/2018/04/uber-agrees-expand-settlement-ftc-related-privacy-case"] },
    { title:"Equifax", date:"2017-07-29", industry:"Finance", type:"Data Breach", impact:"147M records", description:"Unpatched Struts flaw used for exfiltration; landmark case for consumer redress.", sources:["https://www.ftc.gov/equifax-data-breach"] },
    { title:"Facebook–Cambridge Analytica", date:"2018-03-17", industry:"Tech", type:"Data Breach", impact:"Misuse of millions", description:"A data‑harvesting app enabled improper sharing; reshaped privacy rules.", sources:["https://www.ftc.gov/news-events/news/press-releases/2019/07/ftc-imposes-5-billion-penalty-and-sweeping-new-privacy-restrictions-facebook"] },
    { title:"Marriott/Starwood", date:"2018-11-30", industry:"Hospitality", type:"Data Breach", impact:"383M guests", description:"Long‑running intrusion discovered post‑acquisition; included passport data.", sources:["https://oag.ca.gov/ecrime/databreach/report?id=9080"] },
    { title:"Capital One", date:"2019-07-19", industry:"Finance", type:"Data Breach", impact:"100M+ applicants", description:"SSRF + misconfig enabled S3 access; accelerated secure‑by‑default cloud patterns.", sources:["https://www.justice.gov/usao-wdwa/pr/amazon-software-engineer-arrested-data-theft-capital-one"] },
    { title:"Twitter Admin Tool", date:"2020-07-15", industry:"Tech", type:"Data Breach", impact:"High‑profile accounts", description:"Employee social engineering led to admin‑tool misuse and crypto scam.", sources:["https://www.justice.gov/opa/pr/three-charged-international-hack-twitter-accounts"] },
    { title:"SolarWinds SUNBURST", date:"2020-12-13", industry:"Tech", type:"Data Breach", impact:"Thousands of orgs", description:"Compromised Orion updates distributed a backdoor; archetype of supply‑chain risk.", sources:["https://www.cisa.gov/news-events/alerts/2020/12/13/active-exploitation-solarwinds-software"] },

    // Zero-day / Major (20)
    { title:"Code Red", date:"2001-07-13", industry:"Tech", type:"Zero-day", impact:"IIS overflow", description:"Defaced servers and launched DDoS; patches existed but adoption lagged.", sources:["https://en.wikipedia.org/wiki/Code_Red_(computer_worm)"] },
    { title:"Nimda", date:"2001-09-18", industry:"Tech", type:"Zero-day", impact:"Multi‑vector", description:"Propagated via email, web servers, and open shares; stressed defenses.", sources:["https://en.wikipedia.org/wiki/Nimda"] },
    { title:"SQL Slammer", date:"2003-01-25", industry:"Finance", type:"Zero-day", impact:"Internet congestion", description:"Compact UDP worm; ATM outages and major disruption.", sources:["https://en.wikipedia.org/wiki/SQL_Slammer"] },
    { title:"Blaster/Lovsan", date:"2003-08-11", industry:"Tech", type:"Zero-day", impact:"RPC DCOM", description:"Exploited Windows RPC; popularized host firewalls and auto‑updates.", sources:["https://en.wikipedia.org/wiki/Blaster_(computer_worm)"] },
    { title:"Sasser", date:"2004-04-30", industry:"Tech", type:"Zero-day", impact:"LSASS exploit", description:"Spread without email; outages across airlines, hospitals, media.", sources:["https://en.wikipedia.org/wiki/Sasser_(computer_worm)"] },
    { title:"Stuxnet", date:"2010-06-01", industry:"Energy", type:"Zero-day", impact:"ICS sabotage", description:"Multiple zero‑days against centrifuges; reshaped cyber‑physical debate.", sources:["https://www.cisa.gov/news-events/news/stuxnet-and-future-cyber-war"] },
    { title:"Heartbleed", date:"2014-04-07", industry:"Tech", type:"Zero-day", impact:"OpenSSL flaw", description:"Memory disclosure from servers and clients; triggered global patch sprint.", sources:["https://heartbleed.com/"] },
    { title:"Shellshock", date:"2014-09-24", industry:"Tech", type:"Zero-day", impact:"Bash RCE", description:"Environment variable bug led to widespread RCE; layered patches followed.", sources:["https://nvd.nist.gov/vuln/detail/CVE-2014-6271"] },
    { title:"Stagefright", date:"2015-07-27", industry:"Tech", type:"Zero-day", impact:"Android MMS RCE", description:"Vendors coordinated complex update matrix; monthly patch cadence rose.", sources:["https://source.android.com/docs/security/bulletin/2015-08-01"] },
    { title:"Dirty COW", date:"2016-10-19", industry:"Tech", type:"Zero-day", impact:"Linux privesc", description:"Old race condition; active exploitation before disclosure.", sources:["https://dirtycow.ninja/"] },
    { title:"EternalBlue", date:"2017-03-14", industry:"Tech", type:"Zero-day", impact:"SMBv1 RCE", description:"Leaked exploit enabled wormable attacks; powered WannaCry/NotPetya.", sources:["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0144"] },
    { title:"Meltdown & Spectre", date:"2018-01-03", industry:"Tech", type:"Zero-day", impact:"CPU side‑channel", description:"Mitigations spanned microcode, OS, and compilers; performance tradeoffs.", sources:["https://meltdownattack.com/"] },
    { title:"BlueKeep", date:"2019-05-14", industry:"Tech", type:"Zero-day", impact:"Wormable RDP", description:"Pre‑auth RCE; admins rushed to patch or disable services.", sources:["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708"] },
    { title:"Zerologon", date:"2020-08-11", industry:"Tech", type:"Zero-day", impact:"DC takeover", description:"Impersonation via Netlogon bug; rapid exploitation followed.", sources:["https://www.cisa.gov/news-events/alerts/aa20-283a"] },
    { title:"ProxyLogon", date:"2021-03-02", industry:"Tech", type:"Zero-day", impact:"Exchange RCE", description:"Chained bugs enabled pre‑auth RCE and webshell deployment.", sources:["https://www.cisa.gov/news-events/alerts/2021/03/03/compromise-microsoft-exchange-server"] },
    { title:"PrintNightmare", date:"2021-06-29", industry:"Tech", type:"Zero-day", impact:"Spooler RCE", description:"Confusing patches; many disabled printing pending fixes.", sources:["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527"] },
    { title:"ProxyShell", date:"2021-08-12", industry:"Tech", type:"Zero-day", impact:"Mass exploitation", description:"Unauth code execution; attackers deployed webshells and ransomware.", sources:["https://www.cisa.gov/news-events/alerts/2021/08/21/proxyshell-vulnerabilities"] },
    { title:"Log4Shell", date:"2021-12-09", industry:"Tech", type:"Zero-day", impact:"Widespread RCE", description:"Single JNDI lookup enabled trivial RCE across countless Java apps.", sources:["https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a"] },
    { title:"Spring4Shell", date:"2022-03-31", industry:"Tech", type:"Zero-day", impact:"Spring MVC RCE", description:"Cloud platforms issued mitigations and guidance quickly.", sources:["https://tanzu.vmware.com/security/cve-2022-22965"] },
    { title:"XZ Utils Backdoor", date:"2024-03-29", industry:"Tech", type:"Zero-day", impact:"Linux (pre‑GA)", description:"Stealthy backdoor inserted into release tarballs; caught pre‑GA.", sources:["https://www.openwall.com/lists/oss-security/2024/03/29/4"] }
  ,
  { title:"WannaCry", date:"2017-05-12", industry:"Multiple", type:"Ransomware", impact:"Hundreds of thousands of endpoints across 150+ countries", description:"WannaCry weaponized the EternalBlue SMBv1 exploit to spread rapidly. It encrypted files and demanded Bitcoin, causing hospital and business outages. Emergency patches and kill-switch domains helped curb the spread.", sources:["https://en.wikipedia.org/wiki/WannaCry_ransomware_attack"] },
  { title:"NotPetya", date:"2017-06-27", industry:"Multiple", type:"Ransomware", impact:"Global disruption with destructive wiper-like behavior", description:"Delivered via a compromised software update, NotPetya spread laterally with credential theft and EternalBlue. It appeared as ransomware but primarily destroyed data. Losses reached billions and impacted logistics and manufacturing.", sources:["https://en.wikipedia.org/wiki/Petya_(malware)#2017_campaign"] },
  { title:"City of Atlanta \u2013 SamSam", date:"2018-03-22", industry:"Gov", type:"Ransomware", impact:"Municipal services and courts disrupted", description:"SamSam operators gained access and manually deployed encryption. Recovery efforts spanned months and cost tens of millions. The case emphasized patch hygiene and segmentation for city networks.", sources:["https://www.justice.gov/opa/pr/two-iranian-men-charged-deploying-ransomware-extort-hospitals-municipalities-and-public"] },
  { title:"New Orleans \u2013 Ryuk", date:"2019-12-13", industry:"Gov", type:"Ransomware", impact:"City declared state of emergency", description:"Ryuk was deployed following phishing and TrickBot/Emotet activity. Systems were taken offline and incident response mobilized. The event accelerated endpoint hardening and phishing defenses.", sources:["https://www.nola.gov/mayor/news/december-2019/city-of-new-orleans-cyber-security-incident-press/"] },
  { title:"UHS \u2013 Ryuk", date:"2020-09-27", industry:"Healthcare", type:"Ransomware", impact:"Hundreds of hospitals and clinics affected", description:"Universal Health Services experienced widespread IT outages tied to Ryuk. Care continued with downtime procedures while systems were restored. The incident highlighted healthcare\u2019s sensitivity to ransomware.", sources:["https://www.krebsonsecurity.com/2020/09/ryuk-ransomware-attack-hits-hospital-chain-uhs/"] },
  { title:"Acer \u2013 REvil", date:"2021-03-19", industry:"Tech", type:"Ransomware", impact:"Large ransom demand and data leak claims", description:"REvil actors claimed to have stolen Acer data and demanded a record ransom. Reports pointed to vulnerabilities and remote access exposure. The case underscored the risk to OEM supply chains.", sources:["https://www.bleepingcomputer.com/news/security/revil-ransomware-gang-demands-50-million-from-acer/"] },
  { title:"Linode \u2013 Ransom DDoS", date:"2012-01-05", industry:"Tech", type:"Ransomware", impact:"Service disruption via extortion DDoS", description:"Attackers demanded payment to stop sustained DDoS traffic. While not file\u2011encrypting ransomware, the extortion motif prefigured modern tactics. Providers expanded traffic scrubbing and Anycast defenses.", sources:["https://status.linode.com/history"] },
  { title:"LinkedIn Breach", date:"2012-06-05", industry:"Tech", type:"Data Breach", impact:"Millions of hashed passwords exposed", description:"Compromised credentials later recirculated in larger dumps. The incident drove stronger hashing practices and forced resets. It remains a canonical example of password reuse risk.", sources:["https://en.wikipedia.org/wiki/2012_LinkedIn_hack"] },
  { title:"Adobe Breach", date:"2013-10-03", industry:"Tech", type:"Data Breach", impact:"Source code and 100M+ user records", description:"Attackers exfiltrated customer data and source code for several products. Stolen information propagated to underground markets. Code repository security and key rotation were revisited across industry.", sources:["https://krebsonsecurity.com/2013/10/adobe-breach-impacted-at-least-38-million-users/"] },
  { title:"Home Depot POS Breach", date:"2014-09-02", industry:"Retail", type:"Data Breach", impact:"56M payment cards", description:"Custom PoS malware siphoned card data from U.S. and Canadian stores. Attackers used third\u2011party credentials and lateral movement. The breach accelerated EMV adoption and network segmentation.", sources:["https://corporate.homedepot.com/newsroom/home-depot-provides-update-payment-data-breach"] },
  { title:"FriendFinder Networks", date:"2016-11-13", industry:"Tech", type:"Data Breach", impact:"412M accounts", description:"Multiple sites under the FriendFinder Networks umbrella were breached. Data included email addresses and weakly protected passwords. The incident fueled debates on data retention and password storage.", sources:["https://en.wikipedia.org/wiki/FriendFinder_Networks#2016_data_breach"] },
  { title:"Under Armour \u2013 MyFitnessPal", date:"2018-02-22", industry:"Consumer", type:"Data Breach", impact:"150M accounts", description:"Credential and profile data were taken from the fitness app platform. The company disclosed quickly and enforced resets. Users were urged to avoid password reuse across sites.", sources:["https://www.theguardian.com/technology/2018/mar/29/under-armour-data-breach-150-million-myfitnesspal-accounts"] },
  { title:"Desjardins Group", date:"2019-06-20", industry:"Finance", type:"Data Breach", impact:"4.2M customers and 173k businesses", description:"An insider exfiltrated customer records over time. The breach prompted government review and class actions. Financial institutions reexamined insider threat controls.", sources:["https://en.wikipedia.org/wiki/Desjardins_Group#2019_data_breach"] },
  { title:"MOVEit Supply\u2011chain Breaches", date:"2023-05-31", industry:"Tech", type:"Data Breach", impact:"Hundreds of organizations via managed file transfer", description:"A zero\u2011day in MOVEit Transfer enabled mass data theft across customers. Extortion followed with staged leak postings. The campaign became a case study in third\u2011party risk.", sources:["https://www.cisa.gov/news-events/alerts/2023/06/07/cisa-and-fbi-release-advisory-moveit-transfer-vulnerability"] },
  { title:"POODLE", date:"2014-10-14", industry:"Tech", type:"Zero-day", impact:"SSLv3 protocol downgrade attack", description:"The POODLE flaw allowed decryption of secure cookies via padding oracles. Browsers and servers disabled SSLv3 to mitigate. It catalyzed faster retirement of legacy crypto.", sources:["https://www.openssl.org/~bodo/ssl-poodle.pdf"] },
  { title:"FREAK", date:"2015-03-03", industry:"Tech", type:"Zero-day", impact:"Export\u2011grade TLS weakness", description:"FREAK enabled man\u2011in\u2011the\u2011middle downgrades to weak ciphers. Vendors issued patches and hardened defaults. The episode highlighted the long tail of crypto legacy.", sources:["https://freakattack.com/"] },
  { title:"KRACK", date:"2017-10-16", industry:"Tech", type:"Zero-day", impact:"WPA2 key reinstallation attacks", description:"KRACK exploited nonce reuse in WPA2\u2019s 4\u2011way handshake to decrypt traffic. Coordinated patches landed across OSes and routers. The research accelerated the move to WPA3.", sources:["https://www.krackattacks.com/"] },
  { title:"WinRAR ACE Path Traversal", date:"2019-02-20", industry:"Tech", type:"Zero-day", impact:"Code execution via crafted archives", description:"A vulnerable ACE library allowed file writes outside extraction paths. Attackers weaponized the bug in malspam campaigns. Vendors removed ACE support to mitigate risk.", sources:["https://www.checkpoint.com/press-releases/check-point-research-discovers-critical-winrar-vulnerability/"] },
  { title:"Dirty Pipe", date:"2022-03-07", industry:"Tech", type:"Zero-day", impact:"Linux privilege escalation", description:"A kernel flaw enabled overwriting read\u2011only files, escalating privileges. Cloud and Android vendors pushed updates quickly. It underscored the need for rapid kernel patching.", sources:["https://nvd.nist.gov/vuln/detail/CVE-2022-0847"] },
  { title:"regreSSHion", date:"2024-07-01", industry:"Tech", type:"Zero-day", impact:"OpenSSH signal\u2011handler RCE on glibc systems", description:"A regression introduced a pre\u2011auth RCE in recent OpenSSH versions. Distros shipped emergency patches and mitigations. Internet\u2011facing SSH services were urged to update immediately.", sources:["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"] },
  { title:"Bad Rabbit Ransomware", date:"2017-10-24", industry:"Media", type:"Ransomware", impact:"Hundreds of infections across media and transit", description:"Bad Rabbit spread via compromised news sites that pushed a fake Flash installer. Once executed, it encrypted disks and demanded Bitcoin within a strict deadline. Researchers noted code links to Petya/NotPetya and SMB\u2011based lateral movement. The outbreak highlighted drive\u2011by download risks and patch hygiene for enterprise workstations.", sources:["https://www.wired.com/story/bad-rabbit-ransomware-flash-explained"] },
  { title:"Tribune Publishing \u2013 Ryuk", date:"2018-12-28", industry:"Media", type:"Ransomware", impact:"Newspaper printing disrupted across U.S.", description:"Ryuk ransomware impacted Tribune Publishing\u2019s systems used by multiple newspapers, delaying printing and delivery. Reporting indicated malware propagation into shared production environments. The incident showed operational impact beyond data IT teams. Media companies reviewed segmentation and disaster recovery for print and web operations.", sources:["https://www.trendmicro.com/en/what-is/ransomware/ryuk-ransomware.html"] },
  { title:"GandCrab RaaS Campaign", date:"2018-01-29", industry:"Multiple", type:"Ransomware", impact:"Most active RaaS in 2018", description:"GandCrab popularized the modern ransomware\u2011as\u2011a\u2011service affiliate model. Affiliates distributed rapidly evolving builds and split revenue with operators. After a prolific run, the cartel proclaimed retirement in 2019, though code and methods lived on. The campaign influenced the playbooks adopted by later families.", sources:["https://www.fortinet.com/blog/threat-research/gandcrab-threat-actors-retire"] },
  { title:"Ascension Health \u2013 Black Basta", date:"2024-05-08", industry:"Healthcare", type:"Ransomware", impact:"Clinical operations disruptions; millions affected", description:"A ransomware attack attributed to Black Basta disrupted electronic medical records, scheduling, and pharmacy systems across Ascension hospitals. Ambulances were diverted and staff reverted to manual workflows. Subsequent filings reported millions of affected patients. Healthcare guidance urged network segmentation and credential hardening against this actor.", sources:["https://www.reuters.com/technology/cybersecurity/us-hospital-operator-ascension-says-56-million-affected-medical-data-breach-may-2024-12-20/","https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a"] },
  { title:"CNA Financial \u2013 Phoenix CryptoLocker", date:"2021-03-21", industry:"Finance", type:"Ransomware", impact:"Large ransom paid; enterprise outage", description:"CNA Financial suffered a Phoenix CryptoLocker attack that encrypted thousands of devices. Investigations described initial access via a fake browser update and subsequent lateral movement. Media reported a record ransom payment to expedite recovery. The case underscored the danger of \u2018update\u2019 themed social engineering and privilege escalation.", sources:["https://www.bloomberg.com/news/articles/2021-05-20/cna-financial-paid-40-million-in-ransom-after-march-cyberattack","https://www.malwarebytes.com/blog/news/2021/07/cna-legal-filings-lift-the-curtain-on-a-phoenix-cryptolocker-ransomware-attack"] },
  { title:"City Power Johannesburg", date:"2019-07-25", industry:"Energy", type:"Ransomware", impact:"Utility customer services disrupted", description:"Johannesburg\u2019s City Power utility disclosed ransomware that encrypted databases and applications, disrupting prepaid electricity purchases. While core grid operations continued, IT systems required extensive restoration. The episode highlighted municipal utility exposure to commodity ransomware. Public communications emphasized incident triage and customer impact.", sources:["https://www.reuters.com/article/world/johannesburg-power-body-hit-by-ransomware-attack-idUSKCN1UK15G/"] },
  { title:"Philadelphia Inquirer \u2013 Cuba", date:"2023-05-12", industry:"Media", type:"Ransomware", impact:"Publishing and newsroom operations disrupted", description:"The Cuba ransomware group claimed responsibility for a cyberattack that disrupted The Philadelphia Inquirer\u2019s publishing systems. Coverage described offline systems, temporary office closures, and ongoing investigations. Claims of stolen data surfaced and were later removed from the gang\u2019s site. The event reinforced media sector targeting by ransomware crews.", sources:["https://www.bleepingcomputer.com/news/security/cuba-ransomware-claims-cyberattack-on-philadelphia-inquirer/","https://www.inquirer.com/news/philadelphia/philadelphia-inquirer-hack-cyber-disruption-20230514.html"] },
  { title:"Follina MSDT \u2013 CVE-2022-30190", date:"2022-05-31", industry:"Tech", type:"Zero-day", impact:"MS Office preview to code execution", description:"The Follina flaw in Microsoft\u2019s Support Diagnostic Tool allowed remote code execution when Office retrieved crafted templates. Exploitation required only opening or previewing a document in some cases. CISA and Microsoft issued guidance and workarounds before patches were broadly available. The incident renewed focus on living\u2011off\u2011the\u2011land binaries in Windows.", sources:["https://www.cisa.gov/news-events/alerts/2022/05/31/microsoft-releases-workaround-guidance-msdt-follina-vulnerability","https://www.microsoft.com/en-us/msrc/blog/2022/05/guidance-for-cve-2022-30190-microsoft-support-diagnostic-tool-vulnerability"] },
  { title:"Citrix Bleed \u2013 CVE-2023-4966", date:"2023-10-10", industry:"Tech", type:"Zero-day", impact:"Session token theft; MFA bypass scenarios", description:"Citrix Bleed in NetScaler ADC/Gateway leaked memory, enabling theft of session tokens and takeover without credentials. CISA reported active exploitation, including by ransomware affiliates. Vendors urged immediate patching and session resets. The episode demonstrated the operational risk when edge devices expose identity artifacts.", sources:["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a","https://support.citrix.com/external/article/579459/netscaler-adc-and-netscaler-gateway-secu.html"] },
  { title:"Confluence OGNL RCE \u2013 CVE-2021-26084", date:"2021-08-25", industry:"Tech", type:"Zero-day", impact:"Unauthenticated remote code execution", description:"Atlassian disclosed an OGNL injection in Confluence Server/Data Center that allowed unauthenticated RCE. Exploitation in the wild followed quickly, prompting emergency patching and temporary mitigations. The flaw affected a wide range of supported versions. Orgs accelerated WAF rules and internet exposure reviews for collaboration servers.", sources:["https://confluence.atlassian.com/doc/confluence-security-advisory-2021-08-25-1077906215.html","https://nvd.nist.gov/vuln/detail/CVE-2021-26084"] },
  { title:"Fortinet FortiOS SSL\u2011VPN \u2013 CVE-2022-42475", date:"2022-12-12", industry:"Tech", type:"Zero-day", impact:"Remote unauthenticated code execution", description:"A heap overflow in FortiOS SSL\u2011VPN was discovered during incident response, with exploitation observed in the wild. Fortinet released advisories, detection guidance, and signatures as organizations rushed to patch. NVD later detailed affected versions across FortiOS and FortiProxy. The case emphasized monitoring of security appliances for anomalous traffic.", sources:["https://www.fortiguard.com/psirt/FG-IR-22-398","https://nvd.nist.gov/vuln/detail/CVE-2022-42475"] },
  { title:"T\u2011Mobile 2021 Customer Data Breach", date:"2021-08-18", industry:"Telecom", type:"Data Breach", impact:"Tens of millions of records exposed", description:"T\u2011Mobile confirmed a major breach impacting current and prospective customers, including sensitive identifiers. The company published updates and offered identity protection, while regulators and media scrutinized the response. Subsequent settlements and fines followed. The incident became a touchstone for telecom API and perimeter security practices.", sources:["https://www.t-mobile.com/news/network/additional-information-regarding-2021-cyberattack-investigation","https://www.wired.com/story/t-mobile-breach-much-worse-than-it-had-to-be"] }];

  // Normalize
  DATA.forEach(d=>{ d.parsedDate=new Date(d.date); d.year=d.parsedDate.getUTCFullYear();
    if(/zero|cve|shell|day/i.test(d.type)) d.type="Zero-day"; else if(/ransom/i.test(d.type)) d.type="Ransomware"; else d.type="Data Breach"; });

  // Elements
  const fromSel=document.getElementById('fromYearSelect');
  const toSel=document.getElementById('toYearSelect');
  const fromLabel=document.getElementById('fromLabel');
  const toLabel=document.getElementById('toLabel');
  const industrySelect=document.getElementById('industrySelect');
  const typeSelect=document.getElementById('typeSelect');
  const indLabel=document.getElementById('indLabel');
  const typeLabel=document.getElementById('typeLabel');

  // Years 1990..2025
  for(let y=1990;y<=2025;y++){ const f=new Option(String(y),String(y)); if(y===1990) f.selected=true; fromSel.add(f);
    const t=new Option(String(y),String(y)); if(y===2025) t.selected=true; toSel.add(t); }

  // Industry (multi-select)
  const allIndustries=["All"].concat(Array.from(new Set(DATA.map(d=>d.industry))).sort((a,b)=>a.localeCompare(b)));
  allIndustries.forEach(ind=>{ const opt=new Option(ind,ind); if(ind!=="All") opt.selected=true; industrySelect.add(opt); });

  // Attack type select
  const typeOptions=["All","Ransomware","Data Breach","Zero-day"];
  typeOptions.forEach(t=>{ const opt=new Option(t,t); typeSelect.add(opt); });
  typeSelect.value="All";

  function updateLabels(){
    const inds=[...industrySelect.selectedOptions].map(o=>o.value).filter(v=>v!=="All");
    indLabel.textContent = inds.length===0? "(all)" : `${inds.length} selected`;
    const t = typeSelect.value;
    typeLabel.textContent = t==="All" ? "(all)" : t;
  }

  function syncYears(){
    let f=+fromSel.value, t=+toSel.value;
    if(f>t){ if(event && event.target===fromSel){ t=f; toSel.value=String(t);} else { f=t; fromSel.value=String(f);} }
    fromLabel.textContent=String(f); toLabel.textContent=String(t); update();
  }
  fromSel.addEventListener('change', syncYears);
  toSel.addEventListener('change', syncYears);
  industrySelect.addEventListener('change', ()=>{ updateLabels(); update(); });
  typeSelect.addEventListener('change', ()=>{ updateLabels(); update(); });

  // D3 chart
  const svg=d3.select('#chart');
  const margin={top:32,right:28,bottom:72,left:190};
  const width=()=>svg.node().getBoundingClientRect().width - margin.left - margin.right;
  const height=980 - margin.top - margin.bottom;
  const gRoot=svg.append('g');
  const g=gRoot.append('g').attr('transform',`translate(${margin.left},${margin.top})`);
  const gGrid=g.append('g'); const gDots=g.append('g'); const gAxes=g.append('g');

  const industries=Array.from(new Set(DATA.map(d=>d.industry))).sort((a,b)=>a.localeCompare(b));
  const x=d3.scaleTime().domain([new Date('1990-01-01'),new Date('2025-12-31')]).range([0,width()]);
  const y=d3.scaleBand().domain(industries).range([0,height]).paddingInner(0.22);
  const color=d3.scaleOrdinal().domain(TYPES).range(["var(--accent3)","var(--accent)","var(--accent2)"]);
  const xAxis=d3.axisBottom(x).ticks(14).tickSizeOuter(0); const yAxis=d3.axisLeft(y).tickSizeOuter(0);
  const grid=d3.axisBottom(x).ticks(14).tickSize(-height).tickFormat('');

  const $tt=d3.select('#tooltip');
  const showTT=(html, px, py)=>{
    const offset=8; $tt.html(html).style('opacity',1);
    const tt=$tt.node().getBoundingClientRect(); let left=px+offset, top=py+offset;
    const vw=innerWidth, vh=innerHeight;
    if(left+tt.width+12>vw) left=px-tt.width-offset; if(top+tt.height+12>vh) top=py-tt.height-offset;
    if(left<6) left=6; if(top<6) top=6; $tt.style('left',left+'px').style('top',top+'px');
  };
  const hideTT=()=> $tt.style('opacity',0);

  function buildSummary(d){
    const sentences=[];
    if(d.description){
      const parts = d.description.split(/(?<=[.!?])\s+/).filter(Boolean);
      sentences.push(...parts);
    }
    if(d.impact){ sentences.push(`Impact: ${d.impact}.`); }
    sentences.push(`${d.title} highlighted ${d.type.toLowerCase()} risk${d.industry && d.industry!=='Multiple' ? ' in the '+d.industry.toLowerCase()+' sector' : ''}.`);
    sentences.push(`See the source for technical details and timeline.`);
    while(sentences.length<3) sentences.push(`See the source for technical details and timeline.`);
    if(sentences.length>4) sentences.length=4;
    return sentences.join(' ');
  }

  function layoutWithDodge(rows){ const minDX=32, laneSpacing=20; const byInd=d3.group(rows,d=>d.industry);
    rows.forEach(d=>{ d._lane=0; d._lanes=1; });
    byInd.forEach(list=>{
      list.sort((a,b)=>+a.parsedDate-+b.parsedDate); const lanes=[];
      list.forEach(d=>{ const xi=x(d.parsedDate); let lane=0; while(lane<lanes.length && (xi-lanes[lane])<=minDX) lane++; if(lane===lanes.length) lanes.push(-1e9); lanes[lane]=xi; d._lane=lane; });
      const total=lanes.length; list.forEach(d=>d._lanes=total);
    });
    rows.forEach(d=>{ const cy0=y(d.industry)+y.bandwidth()/2; const shift=(d._lane-(d._lanes-1)/2)*laneSpacing; const h = Array.from((d.title+'_'+d.date)).reduce((a,c)=>((a*31+(c.charCodeAt(0)))>>>0),0);
const jitter = ((h % 7) - 3) * 0.8; // -2.4..+2.4 px
d._cy = cy0 + shift + jitter; });
    return rows;
  }

  function resize(){ svg.attr('height', height + margin.top + margin.bottom); x.range([0,width()]); gAxes.selectAll('*').remove(); gGrid.call(grid).selectAll('line').attr('stroke','var(--grid)'); gAxes.append('g').attr('transform',`translate(0,${height})`).call(xAxis).selectAll('text').attr('fill','var(--muted)'); gAxes.append('g').call(yAxis).selectAll('text').attr('fill','var(--muted)'); update(); }
  addEventListener('resize', resize); resize();

  function getFilters(){
    const yFrom=+fromSel.value, yTo=+toSel.value;
    const inds=[...industrySelect.selectedOptions].map(o=>o.value).filter(v=>v!=="All");
    const t=typeSelect.value;
    const types = t==="All" ? ["Ransomware","Data Breach","Zero-day"] : [t];
    return { yFrom, yTo, inds, types };
  }
  function filtered(){
    const { yFrom,yTo,inds,types }=getFilters(); const order={"Ransomware":0,"Data Breach":1,"Zero-day":2};
    return DATA.filter(d=>d.year>=yFrom && d.year<=yTo && (inds.length?inds.includes(d.industry):true) && types.includes(d.type))
               .sort((a,b)=>{ const t=order[a.type]-order[b.type]; return t!==0?t:(a.parsedDate-b.parsedDate); });
  }
  function update(){
    const { yFrom,yTo }=getFilters(); x.domain([new Date(yFrom+'-01-01'),new Date(yTo+'-12-31')]);
    gAxes.selectAll('*').remove(); gGrid.call(grid).selectAll('line').attr('stroke','var(--grid)');
    gAxes.append('g').attr('transform',`translate(0,${height})`).call(xAxis).selectAll('text').attr('fill','var(--muted)');
    gAxes.append('g').call(yAxis).selectAll('text').attr('fill','var(--muted)');
    const rows=layoutWithDodge(filtered());
    const sel=gDots.selectAll('g.dot').data(rows, d=>d.title+'_'+d.date);
    sel.exit().transition().duration(200).style('opacity',0).remove();
    const enter=sel.enter().append('g').attr('class','dot');
    enter.append('circle').attr('r',6).attr('fill',d=>color(d.type)).attr('stroke','#0b0f25').attr('stroke-width',1.5)
      .on('mousemove',function(e,d){
        const summary = buildSummary(d);
        const html=`<h4>${d.title}</h4>
        <div class='meta'>${d.parsedDate.toISOString().slice(0,10)} · <strong>${d.industry}</strong> · ${d.type}</div>
        <p class='desc'>${summary}</p>
        ${d.sources?.length?`<a href='${d.sources[0]}' target='_blank' rel='noopener'>Read more ↗</a>`:''}`;
        const pt=this.getBoundingClientRect();
        showTT(html, pt.left+pt.width/2, pt.top+pt.height/2);
      })
      .on('mouseleave', hideTT)
      .on('click',(e,d)=>{ if(d.sources?.length) window.open(d.sources[0],'_blank','noopener'); });
    const all=enter.merge(sel);
    all.select('circle').transition().duration(350).attr('cx', d=>Math.max(6, Math.min(width()-6, x(d.parsedDate)))).attr('cy', d=>Math.max(6, Math.min(height-6, d._cy))).style('opacity',1);
  }

  updateLabels();
  update();
});