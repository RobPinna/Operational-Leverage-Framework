from __future__ import annotations

from dataclasses import dataclass
from random import Random

from app.connectors.base import EvidencePayload


def scenario_names() -> list[str]:
    return ["RiadGroup Hospitality", "DesertAid NGO"]


@dataclass(slots=True)
class DemoDocumentSeed:
    doc_type: str
    url: str
    title: str
    extracted_text: str
    language: str = "en"
    source_type: str = "html"
    discovered_from: str = "demo seed"


def _jitter(rnd: Random, base: int, spread: int = 6) -> int:
    return max(35, min(95, base + rnd.randint(-spread, spread)))


def _row(
    category: str,
    title: str,
    snippet: str,
    source_url: str,
    base_confidence: int,
    tag: str,
) -> tuple[str, str, str, str, int, str]:
    return category, title, snippet, source_url, base_confidence, tag


def _to_payloads(
    rows: list[tuple[str, str, str, str, int, str]],
    rnd: Random,
    company_name: str,
    domain: str,
) -> list[EvidencePayload]:
    payloads: list[EvidencePayload] = []
    for idx, (category, title, snippet, source_url, base_confidence, tag) in enumerate(rows, start=1):
        payloads.append(
            EvidencePayload(
                connector="demo_seed",
                category=category,
                title=title.format(company=company_name, domain=domain),
                snippet=snippet.format(company=company_name, domain=domain),
                source_url=source_url.format(company=company_name, domain=domain),
                confidence=_jitter(rnd, base_confidence),
                raw={
                    "demo": True,
                    "tag": tag,
                    "scenario_company": company_name,
                    "index": idx,
                },
            )
        )
    return payloads


def _build_riadgroup_rows(domain: str) -> list[tuple[str, str, str, str, int, str]]:
    rows: list[tuple[str, str, str, str, int, str]] = []

    # Exposure and website/public process visibility
    rows.extend(
        [
            _row(
                "exposure",
                "Public contact page lists multi-region booking mailboxes",
                "Contact page exposes addresses such as reservations.gcc@{domain} and groupsales@{domain}.",
                "https://{domain}/contact",
                88,
                "website_contact",
            ),
            _row(
                "exposure",
                "Vendor onboarding PDF references direct finance approval path",
                "Public supplier guide describes invoice escalation path via finance.ap@{domain}.",
                "https://{domain}/vendor-onboarding",
                82,
                "vendor_process",
            ),
            _row(
                "exposure",
                "Privacy page discloses third-party support stack",
                "Privacy notice mentions support tooling and CRM integration providers in public text.",
                "https://{domain}/privacy",
                74,
                "third_party_stack",
            ),
            _row(
                "exposure",
                "Terms page references emergency service reroute channels",
                "Terms indicate fallback communications through shared support inboxes during outages.",
                "https://{domain}/terms",
                71,
                "service_terms",
            ),
            _row(
                "exposure",
                "Careers page publishes recruiter aliases tied to regional offices",
                "Open roles reference recruiter aliases (talent.dxb@{domain}, talent.riyadh@{domain}).",
                "https://{domain}/careers",
                86,
                "careers_contact",
            ),
            _row(
                "exposure",
                "Press kit includes high-resolution invoice-style brand assets",
                "Brand kit provides templates and logos that could aid visual impersonation attempts.",
                "https://{domain}/media/press-kit",
                66,
                "brand_assets",
            ),
        ]
    )

    job_posts = [
        ("Front Office Supervisor - Riyadh", "jobs-gulf-hospitality.example"),
        ("Cluster Reservation Analyst - Dubai", "globalhospitalitytalent.example"),
        ("Guest Relations Manager - Jeddah", "mena-careerboard.example"),
        ("Corporate Accounts Coordinator - Doha", "hospitality-jobs-market.example"),
        ("Revenue Operations Specialist - Muscat", "travelworkstreams.example"),
        ("Procurement Assistant - Abu Dhabi", "ops-careers-hub.example"),
    ]
    for role, host in job_posts:
        rows.append(
            _row(
                "exposure",
                f"External job posting exposes workflow hint: {role}",
                "Posting describes booking verification and billing escalation steps for customer requests.",
                f"https://{host}/companies/riadgroup/{role.lower().replace(' ', '-')}",
                72,
                "job_posting",
            )
        )

    dns_like = [
        "mail gateway points to cloud provider with shared MX pattern",
        "subdomain naming reveals separate booking and loyalty portals",
        "public SPF policy enumerates outsourced mail senders",
        "legacy support hostname still resolves through public DNS",
    ]
    for idx, text in enumerate(dns_like, start=1):
        rows.append(
            _row(
                "exposure",
                f"DNS footprint signal {idx}",
                text,
                f"dns://{domain}/signal/{idx}",
                79,
                "dns_signal",
            )
        )

    # Narrative and mentions
    mention_rows = [
        (
            "HospitalityWire reports customer confusion over duplicate payment reminders",
            "hospitalitywire.example",
            73,
            "news",
        ),
        (
            "RegionalBusinessDesk notes surge in fake booking confirmation screenshots",
            "regionalbusinessdesk.example",
            69,
            "news",
        ),
        (
            "TravelOpsMonitor discusses complaint cluster about callback verification gaps",
            "travelopsmonitor.example",
            67,
            "news",
        ),
        (
            "Forum thread flags suspicious messages claiming urgent reservation updates",
            "guestcommunityhub.example",
            61,
            "community",
        ),
        (
            "Supply chain channel mentions counterfeit partner onboarding requests",
            "vendor-trust-forum.example",
            65,
            "community",
        ),
        (
            "Consumer rights blog cites mismatched sender names in loyalty communications",
            "consumerwatch-gcc.example",
            62,
            "blog",
        ),
        (
            "Travel safety account shares sanitized impersonation warning for guests",
            "socialwatch-hospitality.example",
            58,
            "social",
        ),
        (
            "Industry newsletter highlights hotel group brand abuse in fake invoice campaigns",
            "payments-risk-insights.example",
            71,
            "newsletter",
        ),
    ]
    for idx, (title, host, base, tag) in enumerate(mention_rows, start=1):
        rows.append(
            _row(
                "mention",
                title,
                "Narrative signal references publicly discussed trust and verification concerns.",
                f"https://{host}/stories/riadgroup-{idx}",
                base,
                tag,
            )
        )

    social_threads = [
        "Guest post asks whether support agent should ever request one-time codes.",
        "Travel advisor community shares template for verifying official callbacks.",
        "Corporate booking manager reports fake payment update notices.",
        "Local WhatsApp community warns about cloned booking microsites.",
        "Airline-hotel partner group discusses uncertain sender domains.",
        "Property operations forum flags copied logo usage in fake invoices.",
    ]
    for idx, text in enumerate(social_threads, start=1):
        rows.append(
            _row(
                "mention",
                f"Social narrative thread {idx}",
                text,
                f"https://community-travel-safe.example/thread/rg-{idx}",
                56,
                "social_thread",
            )
        )

    # External contact channels and process exposure
    touchpoints = [
        "Billing external contact channel accepts PDF invoice updates over shared mailbox during peak periods.",
        "Support external contact channel uses callback queue that can be socially imitated without strong verification cues.",
        "Onboarding external contact channel sends unsigned process documents to new B2B clients.",
        "Field operations external contact channel uses ad-hoc SMS updates for service changes.",
        "Loyalty helpdesk external contact channel escalates through manual triage when call volume spikes.",
        "Corporate booking external contact channel relies on partner-facing alias accounts.",
        "Property-level procurement external contact channel permits temporary vendor contacts in urgent workflows.",
        "Customer refund external contact channel references static validation questions.",
        "Event bookings external contact channel routes sensitive approvals through regional shared inboxes.",
        "Guest complaint external contact channel uses mixed channels (email plus messaging apps).",
    ]
    for idx, text in enumerate(touchpoints, start=1):
        rows.append(
            _row(
                "touchpoint",
                f"External contact channel signal {idx}",
                text,
                f"mock://touchpoint/riadgroup/{idx}",
                76,
                "touchpoint",
            )
        )

    # Risk to clients via impersonation (sanitized defensive scenarios only)
    pivots = [
        "Sanitized scenario: attacker imitates billing desk identity to redirect customer payment timing.",
        "Sanitized scenario: fake support callback claims booking profile mismatch and seeks urgency response.",
        "Sanitized scenario: spoofed partner onboarding notice requests process re-validation through unofficial channel.",
        "Sanitized scenario: cloned loyalty notification attempts to trigger credential-reset panic behavior.",
        "Sanitized scenario: fake property operations alert pressures supplier to confirm payment metadata.",
        "Sanitized scenario: event coordinator impersonation targets corporate clients with schedule change narrative.",
        "Sanitized scenario: counterfeit refund status message drives guests to untrusted support paths.",
        "Sanitized scenario: copied brand assets used to social-engineer third-party travel agencies.",
    ]
    for idx, text in enumerate(pivots, start=1):
        rows.append(
            _row(
                "pivot",
                f"Risk to clients via impersonation pattern {idx}",
                text,
                f"mock://pivot/riadgroup/{idx}",
                80,
                "pivot",
            )
        )

    return rows


def _build_desertaid_rows(domain: str) -> list[tuple[str, str, str, str, int, str]]:
    rows: list[tuple[str, str, str, str, int, str]] = []

    rows.extend(
        [
            _row(
                "exposure",
                "Donation page lists regional campaign aliases",
                "Public campaign page references donate.gcc@{domain} and grants@{domain}.",
                "https://{domain}/donate",
                87,
                "donation_contact",
            ),
            _row(
                "exposure",
                "Volunteer onboarding pack is publicly downloadable",
                "Public volunteer guide includes screening and support workflow checkpoints.",
                "https://{domain}/volunteer/onboarding-kit",
                81,
                "volunteer_pack",
            ),
            _row(
                "exposure",
                "Partnership page shows direct escalation contacts for field logistics",
                "Partner resources include named role aliases for emergency coordination.",
                "https://{domain}/partners",
                78,
                "partner_contacts",
            ),
            _row(
                "exposure",
                "Transparency report references multiple donation processors",
                "Report lists donation channels and payment processor routing notes.",
                "https://{domain}/transparency",
                72,
                "processor_disclosure",
            ),
            _row(
                "exposure",
                "Public careers page details beneficiary case-handling workflow",
                "Open positions describe intake validation and callback procedures.",
                "https://{domain}/careers",
                84,
                "careers_workflow",
            ),
            _row(
                "exposure",
                "Press resources include downloadable campaign banner packs",
                "Open media assets could be reused in counterfeit fundraising narratives.",
                "https://{domain}/media",
                67,
                "media_assets",
            ),
        ]
    )

    ngo_jobs = [
        ("Community Outreach Coordinator - Amman", "impactcareers-network.example"),
        ("Field Program Officer - Nairobi", "aidjobs-board.example"),
        ("Safeguarding Analyst - Cairo", "humanitarian-roles.example"),
        ("Donor Communications Associate - Tunis", "global-nonprofit-jobs.example"),
        ("Volunteer Support Specialist - Rabat", "civilsocietytalent.example"),
        ("Grant Operations Assistant - Doha", "reliefcareerline.example"),
    ]
    for role, host in ngo_jobs:
        rows.append(
            _row(
                "exposure",
                f"External NGO job posting reveals external contact channel: {role}",
                "Role text references donor inquiries, volunteer verification and beneficiary escalation patterns.",
                f"https://{host}/organizations/desertaid/{role.lower().replace(' ', '-')}",
                73,
                "job_posting",
            )
        )

    ngo_dns = [
        "mail sender policy includes multiple campaign automation services",
        "legacy subdomain for emergency appeals still publicly indexed",
        "donation forms appear on separate hostnames across regions",
        "name server pattern indicates mixed hosting providers",
    ]
    for idx, text in enumerate(ngo_dns, start=1):
        rows.append(
            _row(
                "exposure",
                f"DNS and hosting signal {idx}",
                text,
                f"dns://{domain}/ngo-signal/{idx}",
                77,
                "dns_signal",
            )
        )

    mention_rows = [
        (
            "AidWatch bulletin highlights fake fundraising pages using similar branding",
            "aidwatch-bulletin.example",
            74,
            "news",
        ),
        (
            "Regional Civic Desk reports beneficiary hotline confusion after lookalike messages",
            "regionalcivicdesk.example",
            70,
            "news",
        ),
        (
            "NGO governance blog discusses trust erosion from impersonated donation drives",
            "ngo-governance-lab.example",
            68,
            "blog",
        ),
        (
            "Volunteer forum shares concerns about unofficial onboarding forms",
            "volunteer-trust-forum.example",
            63,
            "community",
        ),
        (
            "Humanitarian newsletter tracks copycat emergency appeal narratives",
            "humanitarian-signal.example",
            66,
            "newsletter",
        ),
        (
            "Diaspora support channel discusses inconsistent sender addresses",
            "community-relief-circle.example",
            60,
            "community",
        ),
        (
            "Public watchdog post recommends stronger donor verification language",
            "donor-safety-monitor.example",
            62,
            "watchdog",
        ),
        (
            "Social safety account posts sanitized guidance on avoiding fake campaigns",
            "socialtrust-ngo.example",
            57,
            "social",
        ),
    ]
    for idx, (title, host, base, tag) in enumerate(mention_rows, start=1):
        rows.append(
            _row(
                "mention",
                title,
                "Narrative signal indicates external attention to donation and beneficiary trust controls.",
                f"https://{host}/stories/desertaid-{idx}",
                base,
                tag,
            )
        )

    ngo_threads = [
        "Donor community asks how to verify official campaign channels before contributing.",
        "Volunteer moderators report suspicious calls claiming rapid intake approvals.",
        "Beneficiary support forum notes conflicting callback identities.",
        "Grant partners mention fake procurement notices circulating in chat groups.",
        "Field coordination thread flags impersonated logistics updates.",
        "Civil society network shares checklist for validating emergency appeals.",
    ]
    for idx, text in enumerate(ngo_threads, start=1):
        rows.append(
            _row(
                "mention",
                f"NGO social narrative thread {idx}",
                text,
                f"https://community-aid-safety.example/thread/da-{idx}",
                55,
                "social_thread",
            )
        )

    touchpoints = [
        "Donation external contact channel includes regional campaign aliases with manual reconciliation.",
        "Beneficiary hotline external contact channel escalates to callback queue during surge periods.",
        "Volunteer onboarding external contact channel accepts emailed identity documents in legacy flow.",
        "Field logistics external contact channel relies on partner-messaging channels with varied controls.",
        "Emergency appeal external contact channel uses rapid publishing cadence across multiple pages.",
        "Procurement external contact channel handles urgent supplier confirmations through shared inboxes.",
        "Grant reporting external contact channel uses downloadable templates with static authenticity markers.",
        "Donor relations external contact channel mixes automated and manual response channels.",
        "Program intake external contact channel relies on publicly known form distribution windows.",
        "Safeguarding external contact channel routes concerns through region-specific aliases.",
    ]
    for idx, text in enumerate(touchpoints, start=1):
        rows.append(
            _row(
                "touchpoint",
                f"External contact channel signal {idx}",
                text,
                f"mock://touchpoint/desertaid/{idx}",
                75,
                "touchpoint",
            )
        )

    pivots = [
        "Sanitized scenario: impersonated donor-relations message requests urgent donation re-confirmation.",
        "Sanitized scenario: fake volunteer coordinator profile sends unofficial onboarding instructions.",
        "Sanitized scenario: counterfeit emergency appeal update targets diaspora supporter groups.",
        "Sanitized scenario: fraudulent procurement notice imitates aid partner coordination workflow.",
        "Sanitized scenario: spoofed beneficiary support callback claims registration mismatch.",
        "Sanitized scenario: copied campaign visuals used to amplify fake contribution pages.",
        "Sanitized scenario: grant partner receives impersonated compliance reminder via untrusted channel.",
        "Sanitized scenario: social-engineered logistics status update attempts to reroute field actions.",
    ]
    for idx, text in enumerate(pivots, start=1):
        rows.append(
            _row(
                "pivot",
                f"Risk to clients via impersonation pattern {idx}",
                text,
                f"mock://pivot/desertaid/{idx}",
                81,
                "pivot",
            )
        )

    return rows


def _build_generic_rows(company_name: str, domain: str) -> list[tuple[str, str, str, str, int, str]]:
    rows: list[tuple[str, str, str, str, int, str]] = []
    for idx in range(12):
        rows.append(
            _row(
                "exposure",
                f"{company_name} generic exposure signal {idx + 1}",
                "Public-facing information reveals process and contact metadata relevant to reconnaissance.",
                f"https://{domain}/demo/exposure/{idx + 1}",
                72,
                "generic_exposure",
            )
        )
    for idx in range(10):
        rows.append(
            _row(
                "mention",
                f"{company_name} generic narrative signal {idx + 1}",
                "External discussion references trust, communications and verification concerns.",
                f"https://signal-feed.example/{domain}/mention/{idx + 1}",
                60,
                "generic_mention",
            )
        )
    for idx in range(8):
        rows.append(
            _row(
                "touchpoint",
                f"{company_name} generic external contact channel signal {idx + 1}",
                "Operational channel may be vulnerable to impersonation-driven confusion.",
                f"mock://touchpoint/generic/{idx + 1}",
                74,
                "generic_touchpoint",
            )
        )
    for idx in range(6):
        rows.append(
            _row(
                "pivot",
                f"{company_name} generic risk to clients via impersonation signal {idx + 1}",
                "Sanitized scenario indicating potential misuse of organizational identity toward clients or partners.",
                f"mock://pivot/generic/{idx + 1}",
                79,
                "generic_pivot",
            )
        )
    return rows


def generate_demo_evidence(company_name: str, domain: str, seed: int = 7) -> list[EvidencePayload]:
    rnd = Random(seed)
    normalized = company_name.lower()

    if "riadgroup" in normalized:
        rows = _build_riadgroup_rows(domain)
    elif "desertaid" in normalized:
        rows = _build_desertaid_rows(domain)
    else:
        rows = _build_generic_rows(company_name, domain)

    return _to_payloads(rows, rnd, company_name, domain)


def _riadgroup_documents(domain: str) -> list[DemoDocumentSeed]:
    return [
        DemoDocumentSeed(
            doc_type="html",
            url=f"https://{domain}/support",
            title="RiadGroup Support Portal",
            extracted_text=(
                "Support portal lists official channels for guest support, billing clarifications and account management. "
                "Escalation process references tier-2 support queue, callback verification and incident review. "
                "Official contacts include support@{d}, billing@{d}, and corporate-accounts@{d}.".format(d=domain)
            ),
        ),
        DemoDocumentSeed(
            doc_type="html",
            url=f"https://{domain}/careers/cluster-reservation-analyst",
            title="Job Posting - Cluster Reservation Analyst",
            extracted_text=(
                "Job posting describes onboarding process for corporate accounts, ticket triage in Zendesk, "
                "CRM coordination in HubSpot, billing exception workflow, and escalation matrix with account management."
            ),
        ),
        DemoDocumentSeed(
            doc_type="html",
            url=f"https://{domain}/careers/front-office-supervisor",
            title="Job Posting - Front Office Supervisor",
            extracted_text=(
                "Role includes process adherence for guest verification, refund routing, and support escalation. "
                "Mentions service desk toolset, callback validation, and incident communication playbook."
            ),
        ),
        DemoDocumentSeed(
            doc_type="html",
            url=f"https://{domain}/about/org-chart",
            title="Organization Structure and Role Contacts",
            extracted_text=(
                "Organization chart includes roles: Head of Customer Operations, Billing Supervisor, Support Lead, "
                "Regional Account Manager. Public role aliases: ops.office@{d}, support.supervisor@{d}. "
                "No personal direct contacts are published.".format(d=domain)
            ),
        ),
        DemoDocumentSeed(
            doc_type="html",
            url=f"https://{domain}/privacy",
            title="Privacy and Security Notice",
            extracted_text=(
                "Privacy and security policy details acceptable use, data protection measures, and partner processor handling. "
                "Third-party providers include helpdesk and CRM services with documented governance controls."
            ),
        ),
        DemoDocumentSeed(
            doc_type="html",
            url=f"https://{domain}/partners",
            title="Partner and Vendor Onboarding",
            extracted_text=(
                "Partner onboarding notes vendor verification checkpoints, procurement workflows, and invoice review process. "
                "Escalation channel for suspicious identity requests is trust-office@{d}.".format(d=domain)
            ),
        ),
        DemoDocumentSeed(
            doc_type="pdf",
            source_type="pdf",
            url=f"https://{domain}/docs/b2b-onboarding-guide.pdf",
            title="B2B Onboarding Guide",
            extracted_text=(
                "PDF onboarding guide for corporate clients. Includes support external contact channels, onboarding milestones, "
                "billing contact process, and official portal URLs. Contains caution that teams never ask for credentials."
            ),
        ),
        DemoDocumentSeed(
            doc_type="pdf",
            source_type="pdf",
            url=f"https://{domain}/docs/billing-assurance-policy.pdf",
            title="Billing Assurance Policy",
            extracted_text=(
                "PDF policy defines invoice validation flow, approved sender domains, callback verification policy, "
                "and client safety controls against impersonation attempts."
            ),
        ),
        DemoDocumentSeed(
            doc_type="pdf",
            source_type="pdf",
            url=f"https://{domain}/docs/guest-communications-brochure.pdf",
            title="Guest Communications Brochure",
            extracted_text=(
                "Brochure lists official email addresses, support numbers, and booking portal references. "
                "Explains how guests can verify legitimate contact in case of suspicious payment requests."
            ),
        ),
        DemoDocumentSeed(
            doc_type="html",
            url=f"https://{domain}/news/customer-safety-update",
            title="Customer Safety Update",
            source_type="news",
            extracted_text=(
                "News update warns customers about impersonation of billing desk and fake reservation corrections. "
                "Provides defensive verification checklist and official channels."
            ),
        ),
    ]


def _desertaid_documents(domain: str) -> list[DemoDocumentSeed]:
    return [
        DemoDocumentSeed(
            doc_type="html",
            url=f"https://{domain}/support",
            title="Beneficiary and Donor Support Portal",
            extracted_text=(
                "Support portal for donors and beneficiaries includes intake support, donation billing clarifications, "
                "onboarding support for volunteers, and escalation path for suspicious communications."
            ),
        ),
        DemoDocumentSeed(
            doc_type="html",
            url=f"https://{domain}/careers/donor-communications-associate",
            title="Job Posting - Donor Communications Associate",
            extracted_text=(
                "Job posting references CRM workflow, donor helpdesk queue in Zendesk, campaign verification process, "
                "and escalation runbook with safeguarding and finance teams. Mentions payment processor coordination (Stripe metadata only)."
            ),
        ),
        DemoDocumentSeed(
            doc_type="html",
            url=f"https://{domain}/careers/field-program-officer",
            title="Job Posting - Field Program Officer",
            extracted_text=(
                "Role includes beneficiary onboarding workflow, partner coordination process, incident reporting cadence, "
                "and controlled communication channels for urgent field operations."
            ),
        ),
        DemoDocumentSeed(
            doc_type="html",
            url=f"https://{domain}/about/org-chart",
            title="DesertAid Organizational Structure",
            extracted_text=(
                "Roles listed: Donor Relations Lead, Beneficiary Support Manager, Field Logistics Coordinator, Safeguarding Officer. "
                "Contact aliases are generic and channel-based (donor.support@{d}, beneficiary.support@{d}).".format(d=domain)
            ),
        ),
        DemoDocumentSeed(
            doc_type="html",
            url=f"https://{domain}/privacy",
            title="Privacy and Safeguarding Policy",
            extracted_text=(
                "Policy addresses privacy, safeguarding, acceptable use, and controls for protecting donor and beneficiary information. "
                "Includes guidance on authentic communication channels."
            ),
        ),
        DemoDocumentSeed(
            doc_type="html",
            url=f"https://{domain}/acceptable-use",
            title="Acceptable Use and Security Controls",
            extracted_text=(
                "Acceptable use and security controls define official portals, account management responsibilities, "
                "identity assurance steps, and compliance requirements for donor and beneficiary data handling."
            ),
        ),
        DemoDocumentSeed(
            doc_type="html",
            url=f"https://{domain}/partners",
            title="Partner Coordination and Procurement",
            extracted_text=(
                "Public partner guidance explains procurement verification, donation processor coordination, "
                "and escalation contacts for suspicious request patterns."
            ),
        ),
        DemoDocumentSeed(
            doc_type="pdf",
            source_type="pdf",
            url=f"https://{domain}/docs/volunteer-onboarding-handbook.pdf",
            title="Volunteer Onboarding Handbook",
            extracted_text=(
                "Handbook details onboarding checkpoints, identity verification reminders, support channels, and safeguarding escalation. "
                "States volunteers should never submit credentials via email."
            ),
        ),
        DemoDocumentSeed(
            doc_type="pdf",
            source_type="pdf",
            url=f"https://{domain}/docs/donor-safety-guidance.pdf",
            title="Donor Safety Guidance",
            extracted_text=(
                "Donor safety PDF explains how to confirm official campaign identity, validate payment channels, "
                "and report suspected impersonation targeting beneficiaries or supporters."
            ),
        ),
        DemoDocumentSeed(
            doc_type="pdf",
            source_type="pdf",
            url=f"https://{domain}/docs/beneficiary-support-flow.pdf",
            title="Beneficiary Support Flow",
            extracted_text=(
                "Flow document includes beneficiary intake process, support ticket routing, callback checks, "
                "and client-facing partner communication controls."
            ),
        ),
        DemoDocumentSeed(
            doc_type="html",
            url=f"https://{domain}/media/brand-kit",
            title="Official Brand Kit and Channels",
            extracted_text=(
                "Brand kit page lists official campaign assets, verified domains, donor portal URL, support email aliases, "
                "and public social channels used for trusted announcements."
            ),
        ),
        DemoDocumentSeed(
            doc_type="html",
            url=f"https://{domain}/news/trust-advisory",
            title="Trust Advisory",
            source_type="news",
            extracted_text=(
                "Advisory warns about fake donation appeals and impersonated partner notices. "
                "Provides verified channels and defensive awareness guidance."
            ),
        ),
    ]


def generate_demo_documents(company_name: str, domain: str) -> list[DemoDocumentSeed]:
    normalized = company_name.lower()
    if "riadgroup" in normalized:
        return _riadgroup_documents(domain)
    if "desertaid" in normalized:
        return _desertaid_documents(domain)
    return _riadgroup_documents(domain)
