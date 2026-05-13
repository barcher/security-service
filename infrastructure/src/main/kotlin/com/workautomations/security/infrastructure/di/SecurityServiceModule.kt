package com.workautomations.security.infrastructure.di

import org.koin.dsl.module

/**
 * Composition root for the security service.
 *
 * Stream A: empty wiring; only the `/v1/health` route is live.
 * Stream B (SKS-B01..B05): adds mTLS, crypto routes, admin routes.
 * Stream C (SKS-C01..C09): adds persistence + Quartz job bindings.
 *
 * Adapters from `:adapters:outbound:crypto` (MlKemCryptoKeyService, KekProviderPort
 * implementations) bind here once the runtime needs them. Until then the module is
 * intentionally empty — there is no business logic in the composition root.
 */
val securityServiceModule = module { }
