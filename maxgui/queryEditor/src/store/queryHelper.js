/*
 * Copyright (c) 2020 MariaDB Corporation Ab
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file and at www.mariadb.com/bsl11.
 *
 * Change Date: 2026-11-16
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2 or later of the General
 * Public License.
 */
import {
    NODE_TYPES,
    NODE_GROUP_TYPES,
    NODE_GROUP_CHILD_TYPES,
    NODE_NAME_KEYS,
    SYS_SCHEMAS,
} from '@queryEditorSrc/store/config'
import { lodash } from '@share/utils/helpers'
import { t } from 'typy'
import { getObjectRows } from '@queryEditorSrc/utils/helpers'

/**
 * @private
 * @param {Object} node - schema node
 * @returns {String} database name
 */
const getDbName = node => node.qualified_name.split('.')[0]

/**
 * @private
 * @param {Object} node - TRIGGER_G || COL_G || IDX_G node
 * @returns {String} table name
 */
const getTblName = node => node.qualified_name.split('.')[1]

/**
 * @private
 * @returns {String} node key
 */
const genNodeKey = () => lodash.uniqueId('node_key_')

/**
 * @public
 * @param {Object} nodeGroup - A node group. (NODE_GROUP_TYPES)
 * @returns {String} SQL of the node group using for fetching its children nodes
 */
function getNodeGroupSQL(nodeGroup) {
    const { TBL_G, VIEW_G, SP_G, FN_G, TRIGGER_G, COL_G, IDX_G } = NODE_GROUP_TYPES
    const dbName = getDbName(nodeGroup)
    const childNodeType = NODE_GROUP_CHILD_TYPES[nodeGroup.type]

    let colNameKey = NODE_NAME_KEYS[childNodeType],
        tblName = '',
        cols = '',
        from = '',
        cond = ''
    switch (nodeGroup.type) {
        case TRIGGER_G:
        case COL_G:
        case IDX_G:
            tblName = getTblName(nodeGroup)
            break
    }
    switch (nodeGroup.type) {
        case TBL_G:
            cols = `${colNameKey}, CREATE_TIME, TABLE_TYPE, TABLE_ROWS, ENGINE`
            from = 'FROM information_schema.TABLES'
            cond = `WHERE TABLE_SCHEMA = '${dbName}' AND TABLE_TYPE = 'BASE TABLE'`
            break
        case VIEW_G:
            cols = `${colNameKey}, CREATE_TIME, TABLE_TYPE, TABLE_ROWS, ENGINE`
            from = 'FROM information_schema.TABLES'
            cond = `WHERE TABLE_SCHEMA = '${dbName}' AND TABLE_TYPE != 'BASE TABLE'`
            break
        case FN_G:
            cols = `${colNameKey}, DTD_IDENTIFIER, IS_DETERMINISTIC, SQL_DATA_ACCESS, CREATED`
            from = 'FROM information_schema.ROUTINES'
            cond = `WHERE ROUTINE_TYPE = 'FUNCTION' AND ROUTINE_SCHEMA = '${dbName}'`
            break
        case SP_G:
            cols = `${colNameKey}, IS_DETERMINISTIC, SQL_DATA_ACCESS, CREATED`
            from = 'FROM information_schema.ROUTINES'
            cond = `WHERE ROUTINE_TYPE = 'PROCEDURE' AND ROUTINE_SCHEMA = '${dbName}'`
            break
        case TRIGGER_G:
            cols = `${colNameKey}, CREATED, EVENT_MANIPULATION, ACTION_STATEMENT, ACTION_TIMING`
            from = 'FROM information_schema.TRIGGERS'
            cond = `WHERE TRIGGER_SCHEMA='${dbName}' AND EVENT_OBJECT_TABLE = '${tblName}'`
            break
        case COL_G:
            cols = `${colNameKey}, COLUMN_TYPE, COLUMN_KEY, PRIVILEGES`
            from = 'FROM information_schema.COLUMNS'
            cond = `WHERE TABLE_SCHEMA = "${dbName}" AND TABLE_NAME = "${tblName}"`
            break
        case IDX_G:
            // eslint-disable-next-line vue/max-len
            cols = `${colNameKey}, COLUMN_NAME, NON_UNIQUE, SEQ_IN_INDEX, CARDINALITY, NULLABLE, INDEX_TYPE`
            from = 'FROM information_schema.STATISTICS'
            cond = `WHERE TABLE_SCHEMA = "${dbName}" AND TABLE_NAME = "${tblName}"`
            break
    }
    return `SELECT ${cols} ${from} ${cond} ORDER BY ${colNameKey};`
}

/**
 * @private
 * @param {Object} param.nodeGroup - A node group. (NODE_GROUP_TYPES). Undefined if param.type === SCHEMA
 * @param {Object} param.data - data of node
 * @param {String} param.type - type of node to be generated
 * @param {String} param.name - name of the node
 * @returns {Object}  A node in schema sidebar
 */
function genNode({ nodeGroup, data, type, name }) {
    const { SCHEMA, TBL, VIEW, SP, FN, TRIGGER, COL, IDX } = NODE_TYPES
    const { TBL_G, VIEW_G, SP_G, FN_G, COL_G, IDX_G, TRIGGER_G } = NODE_GROUP_TYPES
    const dbName = nodeGroup ? getDbName(nodeGroup) : name
    let node = {
        id: type === SCHEMA ? name : `${nodeGroup.id}.${name}`,
        qualified_name: '',
        key: genNodeKey(),
        type,
        name,
        draggable: true,
        data,
        isSys: SYS_SCHEMAS.includes(dbName.toLowerCase()),
    }
    /**
     * index name can be duplicated. e.g.composite indexes.
     * So this adds -node.key as a suffix to make sure id is unique.
     */
    if (type === IDX) node.id = `${nodeGroup.id}.${name}-${node.key}`

    node.level = lodash.countBy(node.id)['.'] || 0

    switch (type) {
        case TBL:
        case VIEW:
        case SP:
        case FN:
            node.qualified_name = `${dbName}.${node.name}`
            break
        case TRIGGER:
        case COL:
        case IDX:
            node.qualified_name = `${getTblName(nodeGroup)}.${node.name}`
            break
        case SCHEMA:
            node.qualified_name = node.name
            break
    }
    // Assign child node groups
    switch (type) {
        case VIEW:
        case TBL:
            /**
             * VIEW and TBL nodes canBeHighlighted and has children props
             * but only TBL node has TRIGGER_G and IDX_G
             */
            node.canBeHighlighted = true
            node.children = [COL_G, IDX_G, TRIGGER_G].reduce((arr, t) => {
                if (type === VIEW && (t === TRIGGER_G || t === IDX_G)) return arr
                else
                    arr.push({
                        id: `${node.id}.${t}`,
                        qualified_name: `${dbName}.${node.name}.${t}`,
                        key: genNodeKey(),
                        type: t,
                        name: t,
                        draggable: false,
                        level: node.level + 1,
                        children: [],
                    })
                return arr
            }, [])
            break
        case SCHEMA:
            node.children = [TBL_G, VIEW_G, SP_G, FN_G].map(t => ({
                id: `${node.id}.${t}`,
                qualified_name: `${dbName}.${t}`,
                key: genNodeKey(),
                type: t,
                name: t,
                draggable: false,
                level: node.level + 1,
                children: [],
            }))
            break
    }

    return node
}

/**
 * This function returns nodes data for schema sidebar and its completion list for the editor
 * @public
 * @param {Object} param.queryResult - query result data.
 * @param {Object} param.nodeGroup -  A node group. (NODE_GROUP_TYPES)
 * @returns {Object} - return {nodes, cmpList}.
 */
function genNodeData({ queryResult = {}, nodeGroup = null }) {
    const type = nodeGroup ? NODE_GROUP_CHILD_TYPES[nodeGroup.type] : NODE_TYPES.SCHEMA
    const { fields = [], data = [] } = queryResult
    const rows = getObjectRows({ columns: fields, rows: data })
    const nameKey = NODE_NAME_KEYS[type]
    return rows.reduce(
        (acc, row) => {
            acc.nodes.push(
                genNode({
                    nodeGroup,
                    data: row,
                    type,
                    name: row[nameKey],
                })
            )
            acc.cmpList.push({
                label: row[nameKey],
                detail: type.toUpperCase(),
                insertText: row[nameKey],
                type,
            })
            return acc
        },
        { nodes: [], cmpList: [] }
    )
}

/**
 * @public
 * @param {Array} param.treeData - Array of tree nodes to be updated
 * @param {Object} param.nodeId - id of the node to be updated
 * @param {Array} param.children -  Array of children nodes
 * @returns {Array} new tree data
 */
function deepReplaceNode({ treeData, nodeId, children }) {
    return lodash.cloneDeepWith(treeData, value => {
        return value && value.id === nodeId ? { ...value, children } : undefined
    })
}

/**
 * @public
 * @param {Object} node - TBL node
 * @returns {String} - SQL
 */
function getAlterTblOptsSQL(node) {
    const db = getDbName(node)
    const tblName = getTblName(node)
    return `SELECT
                table_name,
                ENGINE AS table_engine,
                character_set_name AS table_charset,
                table_collation,
                table_comment
            FROM
                information_schema.tables t
                JOIN information_schema.collations c ON t.table_collation = c.collation_name
            WHERE
                table_schema = "${db}"
                AND table_name = "${tblName}";`
}

/**
 * @public
 * @param {Object} node - TBL node
 * @returns {String} - SQL
 */
function getAlterColsOptsSQL(node) {
    const db = getDbName(node)
    const tblName = getTblName(node)
    /**
     * Exception for UQ column
     * It needs to LEFT JOIN statistics and table_constraints tables to get accurate UNIQUE INDEX from constraint_name.
     * LEFT JOIN statistics as it has column_name, index_name
     * LEFT JOIN table_constraints as it has constraint_name. There is a sub-query in table_constraints to get
     * get only rows having constraint_type = 'UNIQUE'.
     * Notice: UQ column returns UNIQUE INDEX name.
     *
     */
    return `SELECT
                UUID() AS id,
                a.column_name,
                REGEXP_SUBSTR(UPPER(column_type), '[^)]*[)]?') AS column_type,
                IF(column_key LIKE '%PRI%', 'YES', 'NO') AS PK,
                IF(is_nullable LIKE 'YES', 'NULL', 'NOT NULL') AS NN,
                IF(column_type LIKE '%UNSIGNED%', 'UNSIGNED', '') AS UN,
                IF(c.constraint_name IS NULL, '', c.constraint_name) AS UQ,
                IF(column_type LIKE '%ZEROFILL%', 'ZEROFILL', '') AS ZF,
                IF(extra LIKE '%AUTO_INCREMENT%', 'AUTO_INCREMENT', '') AS AI,
                IF(
                   UPPER(extra) REGEXP 'VIRTUAL|STORED',
                   REGEXP_SUBSTR(UPPER(extra), 'VIRTUAL|STORED'),
                   '(none)'
                ) AS generated,
                COALESCE(generation_expression, column_default, '') AS 'default/expression',
                IF(character_set_name IS NULL, '', character_set_name) AS charset,
                IF(collation_name IS NULL, '', collation_name) AS collation,
                column_comment AS comment
            FROM
                information_schema.columns a
                LEFT JOIN information_schema.statistics b ON (
                   a.table_schema = b.table_schema
                   AND a.table_name = b.table_name
                   AND a.column_name = b.column_name
                )
                LEFT JOIN (
                   SELECT
                      table_name,
                      table_schema,
                      constraint_name
                   FROM
                      information_schema.table_constraints
                   WHERE
                      constraint_type = 'UNIQUE'
                ) c ON (
                   a.table_name = c.table_name
                   AND a.table_schema = c.table_schema
                   AND b.index_name = c.constraint_name
                )
            WHERE
                a.table_schema = '${db}'
                AND a.table_name = '${tblName}'
            GROUP BY
                a.column_name
            ORDER BY
                a.ordinal_position;`
}

/**
 * @public
 * @param {Object} entity - ORM entity object
 * @param {String|Function} payload - either an entity id or a callback function that return Boolean (filter)
 * @returns {Array} returns entities
 */
function filterEntity(entity, payload) {
    if (typeof payload === 'function') return entity.all().filter(payload)
    if (entity.find(payload)) return [entity.find(payload)]
    return []
}
/**
 *
 * @param {Object} apiConnMap - connections from API
 * @param {Array} persistentConns - current persistent connections
 * @returns {Object} - { alive_conn_map: {}, expired_conn_map: {}, orphaned_conn_ids: [] }
 * alive_conn_map: stores connections that exists in the response of a GET to /sql/
 * orphaned_conn_ids: When wke connection expires but its cloned connections (query tabs) are still alive,
 * those are orphaned connections
 */
function categorizeSqlConns({ apiConnMap, persistentConns }) {
    let alive_conn_map = {},
        expired_conn_map = {},
        orphaned_conn_ids = []

    if (!t(apiConnMap).isEmptyObject) {
        persistentConns.forEach(conn => {
            const connId = conn.id
            if (apiConnMap[connId]) {
                // if this has value, it is a cloned connection from the wke connection
                const wkeConnId = t(conn, 'clone_of_conn_id').safeString
                if (wkeConnId && !apiConnMap[wkeConnId]) orphaned_conn_ids.push(conn.id)
                else
                    alive_conn_map[connId] = {
                        ...conn,
                        // update attributes
                        attributes: apiConnMap[connId].attributes,
                    }
            } else expired_conn_map[connId] = conn
        })
    }
    return { alive_conn_map, expired_conn_map, orphaned_conn_ids }
}

export default {
    getNodeGroupSQL,
    genNodeData,
    deepReplaceNode,
    getAlterTblOptsSQL,
    getAlterColsOptsSQL,
    filterEntity,
    categorizeSqlConns,
}