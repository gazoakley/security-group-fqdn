// Import all functions from security-group-fqdn.js
const securityGroupFqdn = require('../../../src/handlers/security-group-fqdn.js');

describe('Test for security-group-fqdn', function () {
    describe('diffPermissions', function () {
        it('returns rules to authorize when none are present', function () {
            var group = { Tags: [] }
            var permissions = []
            var resolved = ['1.2.3.4']
            var result = securityGroupFqdn.diffPermissions(group, permissions, resolved)
            expect(result).toEqual({
                authorize: [
                    {
                        FromPort: 443,
                        IpProtocol: "tcp",
                        IpRanges: [
                            { CidrIp: "1.2.3.4/32" },
                        ],
                        ToPort: 443,
                    },
                ],
                revoke: []
            })
        })

        it('returns rules to revoke when no resolved IPs are present', function () {
            var group = { Tags: [] }
            var permissions = [
                {
                    FromPort: 443,
                    IpProtocol: "tcp",
                    IpRanges: [
                        { CidrIp: "1.2.3.4/32" },
                    ],
                    ToPort: 443,
                }
            ]
            var resolved = []
            var result = securityGroupFqdn.diffPermissions(group, permissions, resolved)
            expect(result).toEqual({
                authorize: [],
                revoke: [
                    {
                        FromPort: 443,
                        IpProtocol: "tcp",
                        IpRanges: [
                            { CidrIp: "1.2.3.4/32" },
                        ],
                        ToPort: 443,
                    }
                ]
            })
        })

        it('returns rules to revoke that do not match configuration', function () {
            var group = { Tags: [] }
            var permissions = [
                {
                    FromPort: 123,
                    IpProtocol: "udp",
                    IpRanges: [
                        { CidrIp: "1.2.3.4/32" },
                    ],
                    ToPort: 456,
                }
            ]
            var resolved = []
            var result = securityGroupFqdn.diffPermissions(group, permissions, resolved)
            expect(result).toEqual({
                authorize: [],
                revoke: [
                    {
                        FromPort: 123,
                        IpProtocol: "udp",
                        IpRanges: [
                            { CidrIp: "1.2.3.4/32" },
                        ],
                        ToPort: 456,
                    }
                ]
            })
        })

        it('returns multiple permissions to revoke when needed', function () {
            var group = { Tags: [] }
            var permissions = [
                {
                    FromPort: 443,
                    IpProtocol: "tcp",
                    IpRanges: [
                        { CidrIp: "1.2.3.4/32" },
                    ],
                    Ipv6Ranges: [
                        { CidrIpv6: '2002::1234:abcd:ffff:c0a8:101/64' },
                    ],
                    ToPort: 443,
                }
            ]
            var resolved = []
            var result = securityGroupFqdn.diffPermissions(group, permissions, resolved)
            expect(result).toEqual({
                authorize: [],
                revoke: [
                    {
                        FromPort: 443,
                        IpProtocol: "tcp",
                        Ipv6Ranges: [
                            { CidrIpv6: '2002::1234:abcd:ffff:c0a8:101/64' },
                        ],
                        ToPort: 443,
                    },
                    {
                        FromPort: 443,
                        IpProtocol: "tcp",
                        IpRanges: [
                            { CidrIp: "1.2.3.4/32" },
                        ],
                        ToPort: 443,
                    }
                ]
            })
        })

        it('returns rules based on configuration', function () {
            var group = {
                Tags: [
                    { Key: securityGroupFqdn.FROM_PORT_TAG, Value: '123' },
                    { Key: securityGroupFqdn.TO_PORT_TAG, Value: '456', },
                    { Key: securityGroupFqdn.PROTOCOL_TAG, Value: 'udp' }
                ]
            }
            var permissions = []
            var resolved = ['1.2.3.4']
            var result = securityGroupFqdn.diffPermissions(group, permissions, resolved)
            expect(result).toEqual({
                authorize: [
                    {
                        FromPort: 123,
                        IpProtocol: "udp",
                        IpRanges: [
                            { CidrIp: "1.2.3.4/32" },
                        ],
                        ToPort: 456,
                    },
                ],
                revoke: []
            })
        })
    });

    describe('getTag', function () {
        it('returns the value for a specified key', function () {
            var group = {
                Tags: [
                    {
                        Key: 'foo',
                        Value: 'bar'
                    }
                ]
            }
            var key = 'foo'
            var result = securityGroupFqdn.getTag(group, key)
            expect(result).toEqual('bar')
        })

        it('returns undefined for a missing key', function () {
            var group = {
                Tags: [
                    {
                        Key: 'foo',
                        Value: 'bar'
                    }
                ]
            }
            var key = 'woo'
            var result = securityGroupFqdn.getTag(group, key)
            expect(result).toEqual(undefined)
        })
    });

    describe('getSetDifference', function () {
        it('returns elements in b not also in a', function () {
            var a = [1, 2, 3]
            var b = [2, 4, 5]
            var result = securityGroupFqdn.getSetDifference(a, b)
            expect(result).toEqual([4, 5])
        });

        it('returns elements in b when none in a', function () {
            var a = []
            var b = [6, 7, 8]
            var result = securityGroupFqdn.getSetDifference(a, b)
            expect(result).toEqual([6, 7, 8])
        });

        it('returns no elements when none in b', function () {
            var a = [0, 1, 2]
            var b = []
            var result = securityGroupFqdn.getSetDifference(a, b)
            expect(result).toEqual([])
        });
    });

    describe('mapPermissions', function () {
        it('returns a IpPermission object for the specified range', function () {
            var fromPort = 123
            var toPort = 456
            var protocol = 'tcp'
            var ranges = ['1.2.3.4/32', '4.5.6.7/32']
            var result = securityGroupFqdn.mapPermission(fromPort, toPort, protocol, ranges)
            expect(result).toEqual({
                FromPort: 123,
                ToPort: 456,
                IpProtocol: 'tcp',
                IpRanges: [
                    { CidrIp: '1.2.3.4/32' },
                    { CidrIp: '4.5.6.7/32' }
                ]
            })
        })
    });

    describe('splitPermission', function () {
        it('returns multple permissions composed of each type', function () {
            var permission = {
                FromPort: 123,
                IpProtocol: "udp",
                IpRanges: [
                    { CidrIp: "1.2.3.4/32" },
                ],
                Ipv6Ranges: [
                    { CidrIpv6: '2002::1234:abcd:ffff:c0a8:101/64' },
                ],
                ToPort: 456,
            }
            var result = securityGroupFqdn.splitPermission(permission)
            expect(result).toEqual([
                {
                    FromPort: 123,
                    IpProtocol: "udp",
                    IpRanges: [
                        { CidrIp: "1.2.3.4/32" },
                    ],
                    ToPort: 456,
                },
                {
                    FromPort: 123,
                    IpProtocol: "udp",
                    Ipv6Ranges: [
                        { CidrIpv6: '2002::1234:abcd:ffff:c0a8:101/64' },
                    ],
                    ToPort: 456,
                }
            ])
        })
    });
});

// function getSetDifference(a, b) {
//     const complements = [];
//     for (const bVal of b) {
//         if (!a.some(aVal => aVal == bVal)) {
//             complements.push(bVal);
//         }
//     }
//     return complements;
// }
