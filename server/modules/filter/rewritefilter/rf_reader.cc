/*
 * Copyright (c) 2022 MariaDB Corporation Ab
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file and at www.mariadb.com/bsl.
 *
 * Change Date: 2026-08-08
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2 or later of the General
 * Public License.
 */

// *uncrustify-off*
/** Rewriter Format (rf)

# The contents of this comment is valid rf.
#
# The rf format for an entry is:
# %%
# [options]
# %
# match template
# %
# replace template
#
# The character '#' starts a single line comment when it is the
# first character on a line.
#
# Options are specified as follows:
# case_sensitive: true
# The colon must stick to the option name.
#
# The separators "%" and "%%" must be the exact content of
# their respective separator lines.
#
# The templates can span multiple lines, the line ending is
# inserted as '\n'. Whitespace does not matter as long as
# ignore_whitespace = true.
# However, note that "id=42" is not the same as "id = 42"
# in the match tamplate even with ignore_whitespace = true.
# The parser cannot know that id=42 should be prepped for
# ignoring space, so it is best to always use space where
# space is allowed.
#
# Nothing needs to be escaped in the templates, except when a
# placeholder regex is defined, where the character '}'
# must be escaped.

# Example:
# All options are set (to their default values, so no actual change)

%%
regex_grammar: Native
case_sensitive: true
what_if: false
continue_if_matched: false
ignore_whitespace: true
%
select count(distinct @{1}) from @{2}
%
select count(*) from (select distinct @{1} from @{2}) as t61763

*/
// *uncrustify-on*

#include "rf_reader.hh"
#include "maxbase/exception.hh"
#include <maxbase/log.hh>
#include <fstream>
#include <array>
#include <functional>

namespace
{

bool starts_with(std::string str, const std::string& prefix)
{
    if (str.length() < prefix.length())
    {
        return false;
    }

    str.resize(prefix.length());
    return str == prefix;
}

const std::string option_case_sensitive = "case_sensitive:";
const std::string option_what_if = "what_if:";
const std::string option_continue_if_matched = "continue_if_matched:";
const std::string option_ignore_whitespace = "ignore_whitespace:";
const std::string option_regex_grammar = "regex_grammar:";

const std::array<std::string, 5> options
{
    option_case_sensitive,
    option_what_if,
    option_continue_if_matched,
    option_ignore_whitespace,
    option_regex_grammar
};

std::pair<std::string, std::string> find_option(std::string line)
{
    maxbase::trim(line);
    auto ite = std::find_if(begin(options), end(options), [&line](const std::string& option){
        for (const auto& s : options)
        {
            return starts_with(line, option);
        }

        return false;
    });

    if (ite != end(options))
    {
        auto value = line.substr(ite->length());
        maxbase::trim(value);

        return {*ite, value};
    }
    else
    {
        return {""s, ""s};
    }
}

// It's a class for the sole reason that the functions need to share line_no.
// The constructor does everything.
class RfReader
{
public:
    RfReader(const std::string& path, const TemplateDef& default_def);
    std::vector<TemplateDef> templates()
    {
        return std::move(m_templates);
    }

private:
    enum class State {Options, MatchTemplate, ReplaceTemplate};

    State set_option(TemplateDef& def, const std::string& line,
                     const std::string& end_line);

    std::string read_template(std::ifstream& in,
                              std::string line,
                              const std::string& end_line);

    bool to_bool(const std::string& value, const std::string& line);

    std::string              m_path;
    std::vector<TemplateDef> m_templates;
    int                      m_line_no = 0;
};

RfReader::RfReader(const std::string& path, const TemplateDef& default_def)
    : m_path(path)
{
    std::ifstream in{m_path};
    if (!in)
    {
        MXB_THROW(RewriteError, "Failed to open rewrite template file: " << m_path);
    }

    TemplateDef def {default_def};
    auto state = State::Options;
    std::string line;

    bool first_template = true;     // Find the first %% to start the state machine
    while (std::getline(in, line))
    {
        ++m_line_no;
        if (line.empty() || line[0] == '#' || (first_template && line != "%%"))
        {
            continue;
        }

        if (first_template)
        {
            first_template = false;
            continue;
        }

        switch (state)
        {
        case State::Options:
            state = set_option(def, line, "%");
            break;

        case State::MatchTemplate:
            def.match_template = read_template(in, line, "%");
            state = State::ReplaceTemplate;
            break;

        case State::ReplaceTemplate:
            def.replace_template = read_template(in, line, "%%");
            check_template_def(def);
            m_templates.push_back(def);
            def = default_def;
            state = State::Options;
        }
    }
}

RfReader::State RfReader::set_option(TemplateDef& def, const std::string& line, const std::string& end_line)
{
    auto [option, value] = find_option(line);

    if (option == option_case_sensitive)
    {
        def.case_sensitive = to_bool(value, line);
    }
    else if (option == option_what_if)
    {
        def.what_if = to_bool(value, line);
    }
    else if (option == option_continue_if_matched)
    {
        def.continue_if_matched = to_bool(value, line);
    }
    else if (option == option_ignore_whitespace)
    {
        def.ignore_whitespace = to_bool(value, line);
    }
    else if (option == option_regex_grammar)
    {
        auto grammar = grammar_from_string(value);
        if (grammar != RegexGrammar::END)
        {
            def.regex_grammar = grammar;
        }
        else
        {
            MXB_THROW(RewriteError, "Invalid regex_grammar value '"
                      << value << "' " << m_path << ':' << m_line_no
                      << " Valid values are '" << valid_grammar_values()
                      << '\'');
        }
    }
    else if (line == end_line)
    {
        return State::MatchTemplate;
    }
    else
    {
        MXB_THROW(RewriteError, "Invalid option '"
                  << line << "' " << m_path << ':' << m_line_no);
    }

    return State::Options;
}

std::string RfReader::read_template(std::ifstream& in,
                                    std::string line,
                                    const std::string& end_line)
{
    std::string lines;

    // This strange looking for() is due to the first line
    // having already been read and it needs the same care
    // that all other lines receive and line_no has already
    // been incremented.
    for (bool first_line = true; in; std::getline(in, line), ++m_line_no, first_line = false)
    {
        if (line.empty() || line[0] == '#')
        {
            continue;
        }

        if (line == end_line)
        {
            break;
        }

        auto p = find_option(line);
        if (!p.first.empty())
        {
            MXB_THROW(RewriteError, "Error option "
                      << p.first << " in template section "
                      << m_path << ':' << m_line_no);
        }

        if (!first_line)
        {
            lines += '\n';
        }
        lines += line;
    }

    return lines;
}

bool RfReader::to_bool(const std::string& value, const std::string& line)
{
    if (value == "false")
    {
        return false;
    }
    else if (value == "true")
    {
        return true;
    }
    else
    {
        MXB_THROW(RewriteError, "Invalid boolean: '"
                  << line << "' "
                  << m_path << ':' << m_line_no
                  << ". Valid values are true and false");
    }
}
}


std::vector<TemplateDef> read_templates_from_rf(const std::string& path,
                                                const TemplateDef& default_def)
{
    RfReader reader(path, default_def);

    return reader.templates();
}