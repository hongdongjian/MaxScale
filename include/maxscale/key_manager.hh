/*
 * Copyright (c) 2020 MariaDB Corporation Ab
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

#include <maxbase/ccdefs.hh>
#include <maxbase/secrets.hh>

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <tuple>
#include <mutex>

namespace maxscale
{
class KeyManager
{
public:

    enum class Type
    {
        // No key manager
        NONE,

        // File based key manager, stores keys locally on disk. Relatively unsafe, use only if you trust file
        // system security. Read https://mariadb.com/kb/en/file-key-management-encryption-plugin/ for more
        // information.
        FILE
    };

    // An abstract class for handling the encryption of the keystore file.
    class MasterKey
    {
    public:
        virtual ~MasterKey() = default;

        virtual std::pair<bool, std::vector<uint8_t>> decrypt(std::vector<uint8_t> input) = 0;

        virtual std::pair<bool, std::vector<uint8_t>> encrypt(std::vector<uint8_t> input) = 0;
    };

    /**
     * Initialize the key manager
     *
     * @return True if the key manager was successful initialized
     */
    static bool init();

    /**
     * Get the latest version of this key
     *
     * @param id The key identifier
     *
     * @return std::tuple with true, the key version and the encryption key if one was found or created.
     *         False if an error occured and the key could not be created.
     */
    std::tuple<bool, uint32_t, std::vector<uint8_t>> latest_key(const std::string& id);

    /**
     * Get a specific version of this key
     *
     * @param id      The key identifier
     * @param version The key version
     *
     * @return std::pair with true and the encryption key if it was found.
     *         False if an error occured or the key was not found.
     */
    std::pair<bool, std::vector<uint8_t>> key(const std::string& id, uint32_t version);

    /**
     * Rotate an encryption key
     *
     * @param id The identifier for the key to be rotated
     *
     * @return True if key rotation was successful
     */
    bool rotate(const std::string& id);

private:
    // Keys mapped to their versions
    using KeyMap = std::map<uint32_t, std::vector<uint8_t>>;

    KeyManager(std::unique_ptr<MasterKey> master_key, std::string keystore);
    bool load_keys();
    bool save_keys();
    bool rotate_key(KeyMap& keymap);

    std::map<std::string, KeyMap> m_keys;       // Keymaps mapped to key IDs
    std::unique_ptr<MasterKey>    m_master_key; // MasterKey implementation
    std::string                   m_keystore;   // Path to the keystore file
    std::mutex                    m_lock;       // Protects m_keys
};

/**
 * Get the global key manager
 *
 * @return The global key manager if one is configured, otherwise nullptr.
 */
KeyManager* key_manager();
}