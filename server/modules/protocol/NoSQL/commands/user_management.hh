/*
 * Copyright (c) 2020 MariaDB Corporation Ab
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file and at www.mariadb.com/bsl11.
 *
 * Change Date: 2025-12-13
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2 or later of the General
 * Public License.
 */

//
// https://docs.mongodb.com/v4.4/reference/command/nav-user-management/
//
#include "defs.hh"
#include <uuid/uuid.h>
#include "../nosqlscram.hh"
#include "../nosqlusermanager.hh"

using namespace std;

namespace nosql
{

namespace command
{

// https://docs.mongodb.com/v4.4/reference/command/createUser/
class CreateUser final : public SingleCommand
{
public:
    static constexpr const char* const KEY = "createUser";
    static constexpr const char* const HELP = "";

    using SingleCommand::SingleCommand;

    ~CreateUser()
    {
        if (m_dcid)
        {
            worker().cancel_delayed_call(m_dcid);
            m_dcid = 0;
        }
    }

    State translate(mxs::Buffer&& mariadb_response, GWBUF** ppNoSQL_response) override final
    {
        State state = State::READY;

        switch (m_action)
        {
        case Action::CREATE:
            state = translate_create(std::move(mariadb_response), ppNoSQL_response);
            break;

        case Action::DROP:
            state = translate_drop(std::move(mariadb_response), ppNoSQL_response);
            break;
        }

        return state;
    }

protected:
    void prepare() override
    {
        m_db = m_database.name();
        m_user += value_as<string>();

        bsoncxx::document::element element;

        element = m_doc[key::PWD];
        if (!element)
        {
            ostringstream ss;
            ss << "Must provide a '" << key::PWD << "' field for all user documents";

            throw SoftError(ss.str(), error::BAD_VALUE);
        }

        auto type = element.type();
        if (type != bsoncxx::type::k_utf8)
        {
            ostringstream ss;
            ss << "\"" << key::PWD << "\" has the wrong type. Expected string, found "
               << bsoncxx::to_string(type);

            throw SoftError(ss.str(), error::TYPE_MISMATCH);
        }

        m_pwd = element.get_utf8();

        element = m_doc[key::ROLES];
        if (!element || (element.type() != bsoncxx::type::k_array))
        {
            ostringstream ss;
            ss << "\"createUser\" command requires a \"" << key::ROLES << "\" array";

            throw SoftError(ss.str(), error::BAD_VALUE);
        }

        check_roles(element.get_array());

        auto& um = m_database.context().um();

        if (um.user_exists(m_db, m_user))
        {
            ostringstream ss;
            ss << "User \"" << m_user << "@" << m_db << "\" already exists";

            throw SoftError(ss.str(), error::LOCATION51003);
        }
    }

    string generate_sql() override
    {
        string user = "'" + m_db + "." + m_user + "'@'%'";
        string pwd(m_pwd.data(), m_pwd.length());

        m_statements.push_back("CREATE USER " + user + " IDENTIFIED BY '" + pwd + "'");

        for (const auto& role : m_roles)
        {
            string db = (role.db == "admin" ? "*" : role.db);

            vector<string> privileges;

            switch (role.id)
            {
            case role::Id::DB_ADMIN:
                privileges.push_back("ALTER");
                privileges.push_back("CREATE");
                privileges.push_back("DROP");
                break;

            case role::Id::READ_WRITE:
                privileges.push_back("DELETE");
                privileges.push_back("INSERT");
                privileges.push_back("UPDATE");
            case role::Id::READ:
                privileges.push_back("SELECT");
                break;

            default:
                mxb_assert(!true);
            }

            string grant = "GRANT " + mxb::join(privileges) + " ON " + db + ".* to " + user;

            m_statements.push_back(grant);
        }

        return mxb::join(m_statements, ";");
    }

private:
    void check_create(const ComResponse& response)
    {
        switch (response.type())
        {
        case ComResponse::OK_PACKET:
            break;

        case ComResponse::ERR_PACKET:
            {
                ComERR err(response);

                switch (err.code())
                {
                case ER_CANNOT_USER:
                    {
                        // We assume it's because the user exists.
                        ostringstream ss;
                        ss << "User \"" << m_user << "\" already exists";

                        throw SoftError(ss.str(), error::LOCATION51003);
                    }
                    break;

                case ER_SPECIFIC_ACCESS_DENIED_ERROR:
                    {
                        ostringstream ss;
                        ss << "not authorized on " << m_database.name() << " to execute command "
                           << bsoncxx::to_json(m_doc);

                        throw SoftError(ss.str(), error::UNAUTHORIZED);
                    }
                    break;

                default:
                    throw MariaDBError(err);
                }
            }
            break;

        default:
            mxb_assert(!true);
            throw_unexpected_packet();
        }
    }

    bool check_grant(const ComResponse& response, int i)
    {
        bool success = true;

        switch (response.type())
        {
        case ComResponse::OK_PACKET:
            break;

        case ComResponse::ERR_PACKET:
            {
                ComERR err(response);

                MXS_ERROR("Could create user '%s.%s'@'%%', but granting access with the "
                          "statement \"%s\" failed with: (%d) \"%s\". Will now attempt to "
                          "DROP the user.",
                          m_db.c_str(),
                          m_user.c_str(),
                          m_statements[i].c_str(),
                          err.code(),
                          err.message().c_str());

                success = false;
            }
            break;

        default:
            mxb_assert(!true);
            throw_unexpected_packet();
        }

        return success;
    }

    State translate_create(mxs::Buffer&& mariadb_response, GWBUF** ppNoSQL_response)
    {
        State state = State::READY;

        uint8_t* pData = mariadb_response.data();
        uint8_t* pEnd = pData + mariadb_response.length();

        size_t i = 0;
        DocumentBuilder doc;

        bool success = true;
        while ((pData < pEnd) && success)
        {
            ComResponse response(&pData);

            if (i == 0)
            {
                check_create(response);
            }
            else
            {
                success = check_grant(response, i);
            }

            ++i;
        }

        if (success)
        {
            mxb_assert(i == m_statements.size());

            auto& um = m_database.context().um();

            vector<uint8_t> salt = crypto::create_random_bytes(scram::SERVER_SALT_SIZE);
            string salt_b64 = mxs::to_base64(salt);

            vector<scram::Mechanism> mechanisms;
            mechanisms.push_back(scram::Mechanism::SHA_1);

            if (um.add_user(m_db, m_user, m_pwd, salt_b64, mechanisms, m_roles))
            {
                doc.append(kvp("ok", 1));
            }
            else
            {
                ostringstream ss;
                ss << "Could add user '" << m_user << "' to the MariaDB database, "
                   << "but could not add the user to the local database " << um.path() << ".";

                string message = ss.str();

                MXS_ERROR("%s", message.c_str());

                throw SoftError(message, error::INTERNAL_ERROR);
            }

            *ppNoSQL_response = create_response(doc.extract());
            state = State::READY;
        }
        else
        {
            // Ok, so GRANTing access failed. To make everything simpler for everyone, will
            // now attempt to DROP the user.

            state = State::BUSY;

            m_action = Action::DROP;
            m_dcid = worker().delayed_call(0, [this](Worker::Call::action_t action) {
                    m_dcid = 0;

                    if (action == Worker::Call::EXECUTE)
                    {
                        string user = "'" + m_db + "." + m_user + "'@'%'";

                        ostringstream sql;
                        sql << "DROP USER '" << m_db << "." << m_user << "'@'%'";

                        send_downstream(sql.str());
                    }

                    return false;
                });
        }

        return state;
    }

    State translate_drop(mxs::Buffer&& mariadb_response, GWBUF** ppNoSQL_response)
    {
        ComResponse response(mariadb_response.data());

        switch (response.type())
        {
        case ComResponse::OK_PACKET:
            {
                ostringstream ss;
                ss << "Could create MariaDB user '" << m_db << "." << m_user << "'@'%', but "
                   << "could not give the required GRANTs. The current used does not have "
                   << "the required privileges. See the MaxScale log for more details.";

                throw SoftError(ss.str(), error::UNAUTHORIZED);
            }
            break;

        case ComResponse::ERR_PACKET:
            {
                ComERR err(response);

                ostringstream ss;
                ss << "Could create MariaDB user '" << m_db << "." << m_user << "'@'%', but "
                   << "could not give the required GRANTs and the subsequent attempt to delete "
                   << "the user failed: (" << err.code() << ") \"" << err.message() << "\". "
                   << "You should now DROP the user manually.";

                throw SoftError(ss.str(), error::INTERNAL_ERROR);
            }
            break;

        default:
            mxb_assert(!true);
            throw_unexpected_packet();
        }

        mxb_assert(!true);
        return State::READY;
    }

    void add_role(const string& db, role::Id role_id)
    {
        m_roles.push_back(role::Role { db, role_id });
    }

    void check_role(const string_view& role_name, const string& db)
    {
        role::Id role_id;
        if (!role::from_string(role_name, &role_id))
        {
            ostringstream ss;
            ss << "No role named " << role_name << "@" << db;

            throw SoftError(ss.str(), error::ROLE_NOT_FOUND);
        }

        add_role(db, role_id);
    }

    void check_role(const string_view& role_name, const string_view& db)
    {
        check_role(role_name, string(db.data(), db.length()));
    }

    void check_role(const string_view& role_name)
    {
        return check_role(role_name, m_database.name());
    }

    void check_role(const bsoncxx::document::view& role_doc)
    {
        auto e = role_doc[key::ROLE];
        if (!e)
        {
            throw SoftError("Missing expected field \"role\"", error::NO_SUCH_KEY);
        }

        if (e.type() != bsoncxx::type::k_utf8)
        {
            ostringstream ss;
            ss << "\"role\" had the wrong type. Expected string, found " << bsoncxx::to_string(e.type());
            throw SoftError(ss.str(), error::TYPE_MISMATCH);
        }

        string_view role_name = e.get_utf8();

        e = role_doc[key::DB];
        if (!e)
        {
            throw SoftError("Missing expected field \"db\"", error::NO_SUCH_KEY);
        }

        if (e.type() != bsoncxx::type::k_utf8)
        {
            ostringstream ss;
            ss << "\"db\" had the wrong type. Expected string, found " << bsoncxx::to_string(e.type());
            throw SoftError(ss.str(), error::TYPE_MISMATCH);
        }

        string_view db = e.get_utf8();

        check_role(role_name, db);
    }

    void check_roles(const bsoncxx::array::view& roles)
    {
        for (const auto& element : roles)
        {
            switch (element.type())
            {
            case bsoncxx::type::k_utf8:
                check_role(element.get_utf8());
                break;

            case bsoncxx::type::k_document:
                check_role(element.get_document());
                break;

            default:
                throw SoftError("Role names must be either strings or objects", error::BAD_VALUE);
            }
        }
    }

private:
    enum class Action
    {
        CREATE,
        DROP
    };

    Action             m_action = Action::CREATE;
    string             m_db;
    string             m_user;
    string_view        m_pwd;
    vector<role::Role> m_roles;
    vector<string>     m_statements;
    uint32_t           m_dcid = { 0 };
};

// https://docs.mongodb.com/v4.4/reference/command/dropAllUsersFromDatabase/
class DropAllUsersFromDatabase final : public ImmediateCommand
{
public:
    static constexpr const char* const KEY = "dropAllUsersFromDatabase";
    static constexpr const char* const HELP = "";

    using ImmediateCommand::ImmediateCommand;

    void populate_response(DocumentBuilder& doc) override
    {
        doc.append(kvp(key::N, 0));
        doc.append(kvp(key::OK, 1));
    }
};

// https://docs.mongodb.com/v4.4/reference/command/dropUser/
class DropUser final : public SingleCommand
{
public:
    static constexpr const char* const KEY = "dropUser";
    static constexpr const char* const HELP = "";

    using SingleCommand::SingleCommand;

    State translate(mxs::Buffer&& mariadb_response, GWBUF** ppNoSQL_response) override final
    {
        ComResponse response(mariadb_response.data());

        DocumentBuilder doc;

        switch (response.type())
        {
        case ComResponse::ERR_PACKET:
            {
                ComERR err(response);

                switch (err.code())
                {
                case ER_CANNOT_USER:
                    {
                        // We assume it's because the user does not exist.
                        ostringstream ss;
                        ss << "User \"" << m_user << "@" << m_db << "\" not found";

                        throw SoftError(ss.str(), error::USER_NOT_FOUND);
                    }
                    break;

                case ER_SPECIFIC_ACCESS_DENIED_ERROR:
                    {
                        ostringstream ss;
                        ss << "not authorized on " << m_database.name() << " to execute command "
                           << bsoncxx::to_json(m_doc);

                        throw SoftError(ss.str(), error::UNAUTHORIZED);
                    }
                    break;

                default:
                    throw MariaDBError(err);
                }
            }
            break;

        case ComResponse::OK_PACKET:
            {
                auto& um = m_database.context().um();

                if (um.remove_user(m_db, m_user))
                {
                    doc.append(kvp("ok", 1));
                }
                else
                {
                    ostringstream ss;
                    ss << "Could remove user \"" << m_user << "@" << m_db << "\" from "
                       << "MariaDB backend, but not from local database.";

                    throw SoftError(ss.str(), error::INTERNAL_ERROR);
                }
            }
            break;

        default:
            mxb_assert(!true);
            throw_unexpected_packet();
        }

        *ppNoSQL_response = create_response(doc.extract());
        return State::READY;
    }

protected:
    void prepare() override
    {
        m_db = m_database.name();
        m_user = value_as<string>();

        auto& um = m_database.context().um();

        if (!um.user_exists(m_db, m_user))
        {
            ostringstream ss;
            ss << "User \"" << m_user << "@" << m_db << "\" not found";

            throw SoftError(ss.str(), error::USER_NOT_FOUND);
        }
    }

    string generate_sql() override
    {
        ostringstream sql;

        sql << "DROP USER '" << m_db << "." << m_user << "'@'%'";

        return sql.str();
    }

private:
    string m_db;
    string m_user;
};

// https://docs.mongodb.com/v4.4/reference/command/grantRolesToUser/

// https://docs.mongodb.com/v4.4/reference/command/revokeRolesFromUser/

// https://docs.mongodb.com/v4.4/reference/command/updateUser/

// https://docs.mongodb.com/v4.4/reference/command/usersInfo/
class UsersInfo : public ImmediateCommand
{
public:
    static constexpr const char* const KEY = "usersInfo";
    static constexpr const char* const HELP = "";

    using ImmediateCommand::ImmediateCommand;

    void populate_response(DocumentBuilder& doc) override
    {
        auto element = m_doc[KEY];

        switch (element.type())
        {
        case bsoncxx::type::k_utf8:
            get_users(doc, m_database.context().um(), element.get_utf8());
            break;

        case bsoncxx::type::k_array:
            get_users(doc, m_database.context().um(), element.get_array());
            break;

        case bsoncxx::type::k_document:
            get_users(doc, m_database.context().um(), element.get_document());
            break;

        case bsoncxx::type::k_int32:
        case bsoncxx::type::k_int64:
        case bsoncxx::type::k_double:
            {
                int32_t value;
                if (element_as<int32_t>(element, Conversion::RELAXED, &value) && (value == 1))
                {
                    get_users(doc, m_database.context().um());
                    break;
                }
            }
            // fallthrough
        default:
            throw SoftError("User and role names must be either strings or objects", error::BAD_VALUE);
        }
    }

private:
    void get_users(DocumentBuilder& doc, const UserManager& um, const string_view& user_name)
    {
        get_users(doc, um, m_database.name(), string(user_name.data(), user_name.length()));
    }

    void get_users(DocumentBuilder& doc, const UserManager& um, const bsoncxx::array::view& users)
    {
        if (users.empty())
        {
            throw SoftError("$and/$or/$nor must be a nonempty array", error::BAD_VALUE);
        }

        vector<string> db_users;

        for (const auto& element: users)
        {
            switch (element.type())
            {
            case bsoncxx::type::k_utf8:
                {
                    string_view user = element.get_utf8();
                    ostringstream ss;
                    ss << m_database.name() << "." << user;
                    auto db_user = ss.str();

                    db_users.push_back(db_user);
                }
                break;

            case bsoncxx::type::k_document:
                {
                    bsoncxx::document::view doc = element.get_document();

                    string user = get_string(doc, key::USER);
                    string db = get_string(doc, key::DB);

                    auto db_user = db + "." + user;

                    db_users.push_back(db_user);
                }
                break;

            default:
                throw SoftError("User and role names must be either strings or objects", error::BAD_VALUE);
            }
        }

        vector<UserManager::UserInfo> infos = um.get_infos(db_users);

        add_users(doc, infos);
        doc.append(kvp(key::OK, 1));
    }

    void get_users(DocumentBuilder& doc, const UserManager& um, const bsoncxx::document::view& user)
    {
        auto name = get_string(doc, key::USER);
        auto db = get_string(doc, key::DB);

        get_users(doc, um, db, name);
    }

    void get_users(DocumentBuilder& doc, const UserManager& um)
    {
        vector<UserManager::UserInfo> infos = um.get_infos(m_database.name());

        add_users(doc, infos);
        doc.append(kvp(key::OK, 1));
    }

    void get_users(DocumentBuilder& doc,
                   const UserManager& um,
                   const string& db,
                   const string& user) const
    {
        ArrayBuilder users;

        UserManager::UserInfo info;
        if (um.get_info(db, user, &info))
        {
            add_user(users, info);
        }

        doc.append(kvp(key::USERS, users.extract()));
        doc.append(kvp(key::OK, 1));
    }

    static void add_users(DocumentBuilder& doc, const vector<UserManager::UserInfo>& infos)
    {
        ArrayBuilder users;

        for (const auto& info : infos)
        {
            add_user(users, info);
        }

        doc.append(kvp(key::USERS, users.extract()));
    }

    static void add_user(ArrayBuilder& users, const UserManager::UserInfo& info)
    {
        ArrayBuilder roles;
        for (const auto& r : info.roles)
        {
            DocumentBuilder role;

            role.append(kvp(key::DB, r.db));
            role.append(kvp(key::ROLE, role::to_string(r.id)));

            roles.append(role.extract());
        }

        ArrayBuilder mechanisms;
        for (const auto& m : info.mechanisms)
        {
            mechanisms.append(scram::to_string(m));
        }

        DocumentBuilder user;
        user.append(kvp(key::_ID, info.db_user));

        uuid_t uuid;
        if (uuid_parse(info.uuid.c_str(), uuid) == 0)
        {
            bsoncxx::types::b_binary user_id;
            user_id.sub_type = bsoncxx::binary_sub_type::k_uuid;
            user_id.bytes = uuid;
            user_id.size = sizeof(uuid);

            user.append(kvp(key::USER_ID, user_id));
        }
        else
        {
            MXS_ERROR("The uuid '%s' of '%s' is invalid.", info.uuid.c_str(), info.db_user.c_str());
        }

        user.append(kvp(key::USER, info.user));
        user.append(kvp(key::DB, info.db));
        user.append(kvp(key::ROLES, roles.extract()));
        user.append(kvp(key::MECHANISMS, mechanisms.extract()));

        users.append(user.extract());
    }

    string get_string(const bsoncxx::document::view& doc, const char* zKey)
    {
        bsoncxx::document::element e = doc[zKey];

        if (!e)
        {
            ostringstream ss;
            ss << "Missing expected field \"" << zKey << "\"";

            throw SoftError(ss.str(), error::NO_SUCH_KEY);
        }

        string s;
        if (!element_as(e, &s))
        {
            ostringstream ss;
            ss << "\"" << zKey << "\" had wrong type. Expected string, found "
               << bsoncxx::to_string(e.type());

            throw SoftError(ss.str(), error::TYPE_MISMATCH);
        }

        return s;
    }
};

}

}
