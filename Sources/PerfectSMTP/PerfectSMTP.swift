//
//  PerfectSMTP.swift
//  PerfectSMTP
//
//  Phase 0 stub. Re-exports the transport-agnostic message/MIME model so
//  `import PerfectSMTP` already gives callers `EmailMessage`,
//  `MIMEComposer`, etc. Channel handlers, the protocol state machine, the
//  connection-pool actor, Transport strategies, and `SMTPMailer`'s public
//  API land in Phase 1 (see Documentation/swift6-nio-rewrite-plan.md §9).
//
@_exported import PerfectSMTPCore
