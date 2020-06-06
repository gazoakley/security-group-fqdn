const EC2 = require('aws-sdk/clients/ec2');
const { Resolver } = require('dns').promises;
const pick = require('lodash.pick');

const INGRESS_TAG = 'security-group-fqdn:ingress'
const EGRESS_TAG = 'security-group-fqdn:egress'
const FROM_PORT_TAG = 'security-group-fqdn:from-port'
const FROM_PORT_DEFAULT = '443'
const TO_PORT_TAG = 'security-group-fqdn:to-port'
const TO_PORT_DEFAULT = '443'
const PROTOCOL_TAG = 'security-group-fqdn:protocol'
const PROTOCOL_DEFAULT = 'tcp'

exports.handler = async (event) => {
    var ec2 = new EC2();

    var params = {
        Filters: [{
            Name: 'tag-key',
            Values: [INGRESS_TAG, EGRESS_TAG]
        }]
    };

    var res = await ec2.describeSecurityGroups(params).promise()

    for (const group of res.SecurityGroups) {
        await updateRules(group, ec2);
    }

    return res;
};

async function updateRules(group, ec2) {
    await updateRulesDirected(group, INGRESS_TAG, group.IpPermissions, params => ec2.authorizeSecurityGroupIngress(params), params => ec2.revokeSecurityGroupIngress(params))
    await updateRulesDirected(group, EGRESS_TAG, group.IpPermissionsEgress, params => ec2.authorizeSecurityGroupEgress(params), params => ec2.revokeSecurityGroupEgress(params))
};

async function updateRulesDirected(group, tag, permissions, authorizeFn, revokeFn) {
    const fqdn = getTag(group, tag);
    if (!fqdn) { return }

    // Query values for FQDN
    const resolver = new Resolver();
    var resolved = [];
    resolved = await resolver.resolve(fqdn);

    // Get permissions changes
    var permissions = diffPermissions(group, permissions, resolved)

    // Permissions to authorize
    if (permissions.authorize.length > 0) {
        var authorizeParams = { GroupId: group.GroupId, IpPermissions: permissions.authorize };
        console.log('Authorize: %o', authorizeParams);
        await authorizeFn(authorizeParams).promise();
    }

    // Permissions to revoke
    if (permissions.revoke.length > 0) {
        var revokeParams = { GroupId: group.GroupId, IpPermissions: permissions.revoke };
        console.log('Revoke: %o', revokeParams);
        await revokeFn(revokeParams).promise();
    }
}

function diffPermissions(group, permissions, resolved) {
    const fromPort = parseInt(getTag(group, FROM_PORT_TAG) || FROM_PORT_DEFAULT);
    const toPort = parseInt(getTag(group, TO_PORT_TAG) || TO_PORT_DEFAULT);
    const protocol = getTag(group, PROTOCOL_TAG) || PROTOCOL_DEFAULT;

    // Get matching IpPermissions
    var matchedPermission;
    var revokePermissions = [];
    for (const permission of permissions) {
        const splitPermissions = splitPermission(permission)
        for (const aPermission of splitPermissions) {
            if (aPermission.FromPort == fromPort &&
                aPermission.ToPort == toPort &&
                aPermission.IpProtocol == protocol &&
                aPermission.hasOwnProperty('IpRanges')) {
                matchedPermission = aPermission;
            } else {
                revokePermissions.push(aPermission);
            }
        }
    }

    var newRanges = resolved.map(ipRange => (ipRange + '/32'));
    var oldRanges = ((matchedPermission && matchedPermission.IpRanges) || []).map(ipRange => ipRange.CidrIp)

    var addRanges = getSetDifference(oldRanges, newRanges);
    var authorizePermissions = [];
    if (addRanges.length > 0) {
        authorizePermissions.push(mapPermission(fromPort, toPort, protocol, addRanges))
    }
    var removeRanges = getSetDifference(newRanges, oldRanges);
    if (removeRanges.length > 0) {
        revokePermissions.push(mapPermission(fromPort, toPort, protocol, removeRanges))
    }

    return {
        authorize: authorizePermissions,
        revoke: revokePermissions
    }
}

function mapPermission(fromPort, toPort, protocol, ranges) {
    return {
        FromPort: fromPort,
        ToPort: toPort,
        IpProtocol: protocol,
        IpRanges: ranges.map(range => { return { CidrIp: range } })
    };
}

function getTag(group, key) {
    for (const tag of group.Tags) {
        if (tag.Key == key) {
            return tag.Value;
        }
    }
}

function getSetDifference(a, b) {
    const complements = [];
    for (const bVal of b) {
        if (!a.some(aVal => aVal == bVal)) {
            complements.push(bVal);
        }
    }
    return complements;
}

function splitPermission(permission) {
    const permissions = []
    const commonProperties = ['FromPort', 'ToPort', 'IpProtocol']
    const splitProperties = ['UserIdGroupPairs', 'IpRanges', 'Ipv6Ranges', 'PrefixListIds']
    for (const splitProperty of splitProperties) {
        if (permission.hasOwnProperty(splitProperty) && permission[splitProperty].length > 0) {
            var pickProperties = commonProperties.concat([splitProperty])
            permissions.push(pick(permission, pickProperties))
        }
    }
    return permissions;
}

Object.assign(exports, {
    FROM_PORT_TAG, TO_PORT_TAG, PROTOCOL_TAG,
    diffPermissions, getTag, getSetDifference, mapPermission, splitPermission
});
