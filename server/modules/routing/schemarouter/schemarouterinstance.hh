/*
 * Copyright (c) 2018 MariaDB Corporation Ab
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file and at www.mariadb.com/bsl11.
 *
 * Change Date: 2024-08-24
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2 or later of the General
 * Public License.
 */
#pragma once

#include "schemarouter.hh"

#include <mutex>
#include <set>
#include <string>

#include <maxscale/router.hh>
#include <maxscale/pcre2.hh>

#include "schemaroutersession.hh"

namespace schemarouter
{

class SchemaRouterSession;

/**
 * The per instance data for the router.
 */
class SchemaRouter : public Router
{
public:
    ~SchemaRouter();
    static SchemaRouter* create(SERVICE* pService, mxs::ConfigParameters* params);
    mxs::RouterSession*  newSession(MXS_SESSION* pSession, const Endpoints& endpoints);
    json_t*              diagnostics() const;
    uint64_t             getCapabilities() const;
    bool                 configure(mxs::ConfigParameters* param);

    mxs::config::Configuration* getConfiguration()
    {
        return nullptr;
    }

private:
    friend class SchemaRouterSession;

    /** Internal functions */
    SchemaRouter(SERVICE* service, SConfig config);

    /** Member variables */
    SConfig      m_config;          /*< expanded config info from SERVICE */
    ShardManager m_shard_manager;   /*< Shard maps hashed by user name */
    SERVICE*     m_service;         /*< Pointer to service */
    std::mutex   m_lock;            /*< Lock for the instance data */
    Stats        m_stats;           /*< Statistics for this router */
};
}
