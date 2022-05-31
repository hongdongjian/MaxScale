/*
 * Copyright (c) 2018 MariaDB Corporation Ab
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file and at www.mariadb.com/bsl11.
 *
 * Change Date: 2026-05-03
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2 or later of the General
 * Public License.
 */
#pragma once

#include <maxscale/ccdefs.hh>
#include <maxscale/key_manager.hh>
#include <maxscale/config2.hh>

class KMIPKey : public mxs::KeyManager::MasterKeyBase
{
public:
    static std::unique_ptr<mxs::KeyManager::MasterKey> create(const mxs::ConfigParameters& options);

    class Config : public mxs::config::Configuration
    {
    public:
        Config();

        std::string host;
        int64_t     port;
        std::string ca;
        std::string cert;
        std::string key;
        std::string id;
    };

    KMIPKey(Config config, std::vector<uint8_t> key);

private:
    Config m_config;
};