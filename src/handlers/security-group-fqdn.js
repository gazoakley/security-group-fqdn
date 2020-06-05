const EC2 = require('aws-sdk/clients/ec2');
const { Resolver } = require('dns').promises;

exports.handler = async(event) => {
    var ec2 = new EC2();

    var params = {
        Filters: [{
            Name: "tag-key",
            Values: [
                "gazoakley:security-group-ingress",
                "gazoakley:security-group-egress"
            ]
        }]
    };

    var res = await ec2.describeSecurityGroups(params).promise()

    for (const group of res.SecurityGroups) {
        await updateRules(group, ec2);
    }

    return res;
};

async function updateRules(group, ec2) {
    const fqdn = getTag(group, 'gazoakley:security-group-egress');

    // Query values for FQDN
    const resolver = new Resolver();
    var resolved = [];
    try {
        resolved = await resolver.resolve(fqdn);
    }
    catch (e) {
        console.warn(e);
    }
    console.log(resolved);

    var permissions = diffRules(group, fromPort, toPort, protocol)

    // Rules to add
    if (permissions.authorize.length > 0) {
        var authorizeParams = { GroupId: group.GroupId, IpPermissions: permissions.authorize };
        console.log('authorizeParams:', JSON.stringify(authorizeParams, null, 2));
        await ec2.authorizeSecurityGroupEgress(authorizeParams).promise();
    }

    // Rules to remove
    if (permissions.revoke.length > 0) {
        var revokeParams = { GroupId: group.GroupId, IpPermissions: permissions.revoke };
        console.log('revokeParams:', JSON.stringify(revokeParams, null, 2));
        await ec2.revokeSecurityGroupEgress(revokeParams).promise();
    }
};

function diffRules(group, resolved) {
    console.log(group.GroupName);
    const fromPort = parseInt(getTag(group, 'gazoakley:security-group-egress-from-port') || '443');
    const toPort = parseInt(getTag(group, 'gazoakley:security-group-egress-to-port') || '443');
    const protocol = getTag(group, 'gazoakley:security-group-egress-protocol') || 'tcp';

    // Get matching IpPermissions
    var matchPermissions;
    var revokePermissions = [];
    for (const permissions of group.IpPermissionsEgress) {
        console.log('permissions:', permissions)
        if (permissions.FromPort == fromPort &&
            permissions.ToPort == toPort &&
            permissions.IpProtocol == protocol) {
            matchPermissions = permissions;
            console.log('matchPermissions:', matchPermissions);
        }
        else {
            // revokePermissions.push(permissions);
        }
    }

    var newRanges = resolved.map(ipRange => (ipRange + '/32'));
    console.log('newRanges:', newRanges);
    var oldRanges = ((matchPermissions && matchPermissions.IpRanges) || []).map(ipRange => ipRange.CidrIp)
    console.log('oldRanges:', oldRanges);
    
    var addRanges = getSetDifference(oldRanges, newRanges);
    console.log('addRanges:', addRanges);
    var authorizePermissions = [];
    if (addRanges.length > 0) {
        authorizePermissions.push({
            FromPort: fromPort,
            ToPort: toPort,
            IpProtocol: protocol,
            IpRanges: addRanges.map(range => { return { CidrIp: range } })
        });
    }
    var removeRanges = getSetDifference(newRanges, oldRanges);
    console.log('removeRanges:', removeRanges);
    if (removeRanges.length > 0) {
        revokePermissions.push({
            FromPort: fromPort,
            ToPort: toPort,
            IpProtocol: protocol,
            IpRanges: removeRanges.map(range => { return { CidrIp: range } })
        })
    }

    return {
        authorize: authorizePermissions,
        revoke: revokePermissions
    }
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
