# Alpine Wall User's Guide

## Configuration File Processing

[Alpine Wall](http://wiki.alpinelinux.org/wiki/Alpine_Wall) (awall)
reads its configuration from multiple JSON-formatted files, called
*policy files*. The files located in directory
`/usr/share/awall/mandatory` are *mandatory* policies shipped with APK
packages. In addition, there can be installation-specific mandatory
policies in `/etc/awall`.

The latter directory may also contain symbolic links to policy files
located in `/usr/share/awall/optional` and
`/etc/awall/optional`. These are *optional* policies, which can be
enabled on need basis. Such symbolic links are easily created and
destroyed using the `awall enable` and `awall disable`
commands. `awall list` shows which optional policies are enabled and
disabled. The command also prints the description of the optional
policy if defined in the file using a top-level attribute named
**description**.

Sometimes a policy file depends on other policy files. In this case,
the policy file must have a top-level attribute **import**, the value
of which is a list of policy names, which correspond to the file names
without the `.json` suffix. The imported policies may be either
optional policies or *private* policies, located in
`/usr/share/awall/private` or `/etc/awall/private`. By default, the
policies listed there are processed before the importing policy.

The order of the generated iptables rules generally reflects the
processing order of their corresponding awall policies. The processing
order of policies can be adjusted by defining top-level attributes
**after** and **before** in policy files. These attributes are lists
of policies, after or before which the declaring policy shall be
processed. Putting a policy name to either of these lists does not by
itself import the policy. The ordering directives are ignored with
respect to those policies that are not enabled by the user or imported
by other policies. If not defined, **after** is assumed to be equal to
the relative complement of the **before** definition in the **import**
definition of the policy.

As the import directive does not require the path name to be
specified, awall expects policies to have unique names, even if
located in different directories. It is allowed to import optional
policies that are not explicitly enabled by the user. Such policies
show up with the `required` status in the output of `awall list`.

## List Parameters

Several awall parameters are defined as lists of values. In order to
facilitate manual editing of policy files, awall also accepts single
values in place of lists. Such values are semantically equivalent to
lists containing one element.

## Variable Expansion

Awall allows variable definitions in policy files. The top-level
attribute **variable** is a dictionary containing the definitions. The
value of a variable can be of any type (string, integer, list, or
dictionary).

A variable is referenced in policy files by a string which equals the
variable name prepended with the **$** character. If the value of the
variable is a string, the reference can be embedded into a longer
string in order to substitute some part of that string (in shell
style). Variable references can be used when defining other variables,
as long as the definitions are not circular.

Policy files can reference variables defined in other policy
files. Policy files can also override variables defined elsewhere by
redefining them. In this case, the new definition affects all policy
files, also those processed before the overriding policy. Awall
variables are in fact simple macros, since each variable remains
constant thoughout a single processing round. If multiple files define
the same variable, the definition in the file processed last takes
effect.

If defined as an empty string, all non-embedded references to a
variable evaluate as if the attribute in question was not present in
the configuration. This is also the case when a string containing
embedded variable references finally evaluates to an empty string.

## Configuration Objects

Configuration objects can be divided into two main types. *Auxiliary
objects* model high-level concepts such as services and zones. *Rule
objects* translate into one or more iptables rules, and are often
defined with the help of some auxiliary objects.

### Services

A *service* represents a set of network protocols. A top-level
attribute **service** is a dictionary that maps service names to
service definition objects, or lists thereof in more complex cases.

A service definition object contains an attribute named **proto**,
which corresponds to the `--protocol` option of iptables. The protocol
can be defined as a numerical value or string as defined in
`/etc/protocols`. If the protocol is **tcp** or **udp**, the scope of
the service definition may be constrained by defining an attribute
named **port**, which is a list of TCP or UDP port numbers or ranges
thereof, separated by the **-** character. If the protocol is **icmp**
or **icmpv6**, an analogous **type** attribute may be used. The
replies to ICMP messages have their own type codes, which may be
specified using the **reply-type** attribute.

If the protocol is **icmp** or **icmpv6**, the scope of the rule is
also automatically limited to IPv4 or IPv6, respectively. There are
also other services which are specific to IPv4 or IPv6. To constrain
the scope of the service definition to either protocol version, an
optional **family** attribute can be set to value **inet** or
**inet6**, respectively.

Some services require the server or client to open additional
connections to dynamically allocated ports or even different
hosts. *Connection tracking helpers* are used to make the firewall
aware of such additional connections. The **ct-helper** attribute is
used to associate such a helper to a service definition when required
by the service.

All rule objects, except for policies, may have an attribute named
**service**, constraining the rule's scope to specific services
only. This attribute is a list of service names, referring to the keys
of the top-level service dictionary.

### <a name="zone"></a>Zones

A *zone* represents a set of network hosts. A top-level attribute
**zone** is a dictionary that maps zone names to zone objects. A zone
object has an attribute named **iface**, **addr**, or both. **iface**
is a list of network interfaces and **addr** is a list of IPv4/IPv6
host and network addresses (CIDR notation). **addr** may also contain
domain names, which are expanded to IP addresses using DNS
resolution. If not defined, **addr** defaults to the entire address
space and **iface** to all interfaces. An empty zone can be defined by
setting either **addr** or **iface** to an empty list.

Rule objects contain two attributes, **in** and **out**, which are
lists of zone names. These attributes control whether a packet matches
the rule or not. If a particular zone is referenced by the **in**
attribute, the rule applies to packets whose ingress interface and
source address are covered by the zone definition. Correspondingly, if
a zone is referenced by the **out** attribute, the rule applies to
packets whose egress interface and destination address are included in
the zone. If both **in** and **out** are defined, the packet must
fulfill both criteria in order to match the rule.

The firewall host itself can be referred to using the special value
**_fw** as the zone name.

By default, awall does not generate iptables rules with identical
ingress and egress interfaces. This behavior can be changed per zone
by setting the optional **route-back** attribute of the zone to
**true**. Note that this attribute can have an effect also in the case
where **in** and **out** attributes of a rule are not equal but their
definitions overlap. In this case, the **route-back** attribute of the
**out** zone determines the behavior.

### <a name="limit"></a>Limits

A *limit* specifies the maximum rate for a flow of packets or new
connections. Unlike the other auxiliary objects, limits are not named
members of a top-level dictionary but are embedded into other objects.

In its simplest form, a limit definition is an integer specifying the
maximum number of packets or connections per second. More complex
limits are defined as objects, where the **count** attribute define
the maximum during an interval defined by the **interval**
attribute. The unit of the **interval** attribute is second, and the
default value is 1.

The maximum rate defined by a limit may be absolute or specific to
blocks of IP addresses or pairs thereof. The number of most
significant bits taken into account when mapping the source and
destination IP addresses to blocks can be specified with the **mask**
attribute. The **mask** attribute is an object with two attributes
defining the prefix lengths, named **src** and
**dest**. Alternatively, the **mask** object may have object
attributes named **inet** and **inet6** which contain address
family&ndash;specific prefix length pairs. If **mask** is defined as
an integer, it is interpreted as the source address prefix length.

The default value for **mask** depends on the type of the enclosing
object. For [filters](#filter), the default behavior is to apply the
limit for each source address separately. For [logging classes](#log),
the limit is considered absolute by default.

### <a name="log"></a>Logging Classes

A *logging class* specifies how packets matching certain rules are
logged. A top-level attribute **log** is a dictionary that maps
logging class names to setting objects.

A setting object may have an attribute named **mode**, which specifies
which logging facility to use. Allowed values are **log**, **nflog**,
and **ulog**. The default is **log**, i.e. in-kernel logging.

The following table shows the optional attributes valid for all
logging modes:

<table>
  <thead><tr><th>Attribute</th><th>Description</th></tr></thead>
  <tbody>
    <tr>
      <td><strong>every</strong></td>
      <td>
        Divide successive packets into groups, the size of which is
        specified by the value of this attribute, and log only the
        first packet of each group
      </td>
    </tr>
    <tr>
      <td><strong>limit</strong></td>
      <td>
        Maximum number of packets to be logged defined as <a
        href="#limit">limit</a>
      </td>
    </tr>
    <tr>
      <td><strong>prefix</strong></td>
      <td>String with which the log entries are prefixed</td>
    </tr>
    <tr>
      <td><strong>probability</strong></td>
      <td>Probability for logging an individual packet (default: 1)</td>
    </tr>
  </tbody>
</table>

With the in-kernel log mode **log**, the level of logging may be
specified using the **level** attribute. Log modes **nflog** and
**ulog** are about copying the packets into user space, at least
partially. The following table shows the additional attributes valid
with these modes:

<table>
  <thead><tr><th>Attribute</th><th>Description</th></tr></thead>
  <tbody>
    <tr><td><strong>group</strong></td><td>Netlink group to be used</td></tr>
    <tr>
      <td><strong>range</strong></td><td>Number of bytes to be copied</td>
    </tr>
    <tr>
      <td><strong>threshold</strong></td>
      <td>Number of packets to queue inside the kernel before copying them</td>
    </tr>
  </tbody>
</table>

[Filter](#filter) and [policy](#policy) rules can have an attribute
named **log**. If it is a string, it is interpreted as a reference to
a logging class, and logging is performed according to the
definitions. If the value of the **log** attribute is **true**
(boolean), logging is done using default settings. If the value is
**false** (boolean), logging is disabled for the rule. If **log** is
not defined, logging is done using the default settings except for
accept rules, for which logging is omitted.

Default logging settings can be set by defining a logging class named
**_default**. Normally, default logging uses the **log** mode with
packets limited to one per second.

### Rules

There are several types of rule objects:

* Filter rules
* Policy rules
* Packet Logging rules
* NAT rules
* Packet Marking rules
* Transparent Proxy rules
* MSS Clamping rules
* Connection Tracking Bypass rules

All rule objects can have the **in** and **out** attributes referring
to [zones](#zone) as described in the previous section. In addition,
the scope of the rule can be further constrained with the following
attributes:

<table>
  <thead><tr><th>Attribute</th><th>Description</th><th>Effect</th></tr></thead>
  <tbody>
    <tr>
      <td><strong>src</strong></td>
      <td>
        Similar to <strong>addr</strong> attribute of <a
        href="#zone">zone objects</a>
      </td>
      <td>Packet's source address matches the value</td>
    </tr>
    <tr>
      <td><strong>dest</strong></td>
      <td>
        Similar to <strong>addr</strong> attribute of <a
        href="#zone">zone objects</a>
      </td>
      <td>Packet's destination address matches the value</td>
    </tr>
    <tr>
      <td><strong>ipset</strong></td>
      <td>
        Object containing two attributes: <strong>name</strong>
        referring to an <a href="#ipset">IP set</a> and
        <strong>args</strong>, which is a list of strings
        <strong>in</strong> and <strong>out</strong>
      </td>
      <td>
        Packet matches the IP set referred here when the match
        arguments are taken from the source (<strong>in</strong>) and
        destination (<strong>out</strong>) address or port in the
        order specified by <strong>args</strong>
      </td>
    </tr>
    <tr>
      <td><strong>ipsec</strong></td>
      <td><strong>in</strong> or <strong>out</strong></td>
      <td>
        IPsec decapsulation perfomed on ingress (<strong>in</strong>)
        or encapsulation performed on egress (<strong>out</strong>)
      </td>
    </tr>
  </tbody>
</table>

Rule objects are declared in type-specific top-level dictionaries in
awall policy files. If a packet matches multiple rules, the one
appearing earlier in the list takes precedence. If the matching rules
are defined in different policy files, the one that was processed
earlier takes precedence in the current implementation, but this may
change in future versions.

#### <a name="filter"></a>Filter Rules

Filter objects specify an action for packets fulfilling certain
criteria. The top-level attribute **filter** is a list of filter
objects.

Filter objects must have an attribute named **action**, the value of
which can be one of the following:

<table>
  <thead><tr><th>Value</th><th>Action</th></tr></thead>
  <tbody>
    <tr>
      <td><strong>accept</strong></td><td>Accept the packet (default)</td>
    </tr>
    <tr>
      <td><strong>reject</strong></td>
      <td>Reject the packet with an ICMP error message</td>
    </tr>
    <tr><td><strong>drop</strong></td><td>Silently drop the packet</td></tr>
    <tr>
      <td><strong>tarpit</strong></td>
      <td>
        Put incoming TCP connections into persist state and ignore
        attempts to close them. Silently drop non-TCP
        packets. (Connection tracking bypass is automatically enabled
        for the matching packets.)
      </td>
    </tr>
  </tbody>
</table>

Filter objects, the action of which is **accept**, may also contain
limits for packet flow or new connections. These are specified with
the **flow-limit** and **conn-limit** attributes, respectively. The
values of these attributes are [limit objects](#limit). The **drop**
action is applied to the packets exceeding the limit. Optionally, the
limit object may have an attribute named **log**. It defines how the
dropped packets should be logged and is semantically similar to the
**log** attribute of rule objects.

Filter objects may have an attribute named **dnat**, the value of
which is an IPv4 address. If defined, this enables destination NAT for
all IPv4 packets matching the rule, such that the specified address
replaces the original destination address. If also port translation is
desired, the attribute may be defined as an object consisting of
attributes **addr** and **port**. The format of the **port** attribute
is similar to that of the **to-port** attribute of [NAT
rules](#nat). This option has no effect on IPv6 packets.

Filter objects may have a boolean attribute named **no-track**. If set
to **true**, connection tracking is bypassed for the matching
packets. In addition, if **action** is set to **accept**, the
corresponding packets travelling to the reverse direction are also
allowed.

If one or more connection tracking helpers are associated with the
services referred to by an accept rule, additional iptables rules are
generated for the related connections detected by the helpers. The
**related** attribute can be used to override the default rules
generated by awall. It is a list of basic rule objects, the packets
matching to which are accepted, provided that they are also detected
by at least one of the helpers.

#### <a name="policy"></a>Policy Rules

Policy objects describe the default action for packets that did not
match any filter. The top-level attribute **policy** is a list of
policy objects.

Policy objects must have the **action** attribute defined. The
possible values and their semantics are the same as in [filter
rules](#filter).

#### Packet Logging Rules

Packet logging rules allow packets matching the specified criteria to
be logged before any filtering takes place. Such rules are contained
in the top-level list named **packet-log**.

Logging class may be specified using the **log** attribute. Otherwise,
default logging settings are used.

#### <a name="nat"></a>NAT Rules

NAT rules come in two flavors: *source NAT rules* and *destination NAT
rules*. These are contained in two top-level lists named **snat** and
**dnat**, respectively.

Each NAT rule may have an attribute named **to-addr** that specifies
the IPv4 address range to which the original source or destination
address is mapped. The value can be a single IPv4 address or a range
specified by two addresses, separated with the **-** character. If not
defined, it defaults to the primary address of the ingress interface
in case of destination NAT, or that of the egress interface in case of
source NAT.

Optionally, a NAT rule can specify the TCP and UDP port range to which
the original source or destination port is mapped. The attribute is
named **to-port**, and the value can be a single port number or a
range specified by two numbers, separated with the **-** character. If
**to-port** is not specified, the original port number is kept intact.

NAT rules, may have an **action** attribute set to value **include**
or **exclude**. The latter means that NAT is not performed on the
matching packets (unless they match an **include** rule processed
earlier). The default value is **include**.

#### Packet Marking Rules

Packet marking rules are used to mark incoming packets matching the
specified criteria. The mark can be used as a basis for the routing
decision. Each marking rule must specify the mark using the **mark**
attribute, which is a 32-bit integer.

Normal marking rules are contained by the top-level list attribute
named **mark**.

There is another top-level list attribute, named **route-track**,
which contains route tracking rules. These are special marking rules
which cause all the subsequent packets related to the same connection
to be marked according to the rule.

#### Transparent Proxy Rules

Transparent proxy rules divert the matching packets to a local proxy
process without altering their headers. Such rules are contained in
the top-level list named **tproxy**.

In addition to the firewall configuration, using a transparent proxy
requires a routing configuration where packets marked for proxying are
diverted to a local process. The **awall_tproxy_mark** variable can be
used to specify the mark for such packets, which defaults to 1.

Proxy rules may also have an attribute named **to-port** for
specifying the TCP or UDP port of the proxy if it is different from
the original destination port.

#### MSS Clamping Rules

MSS Clamping Rules are used to deal with ISPs that block ICMP
Fragmentation Needed or ICMPv6 Packet Too Big packets. An MSS clamping
rule overwrites the MSS option with a value specified with the **mss**
attribute for the matching TCP connections. If **mss** is not
specified, a suitable value is automatically determined from the path
MTU. The MSS clamping rules are located in the top-level dictionary
named **clamp-mss**.

#### Connection Tracking Bypass Rules

Connection tracking bypass rules are used to disable connection
tracking for packets matching the specified criteria. The top-level
attribute **no-track** is a list of such rules.

Like [NAT rules](#nat), connection tracking bypass rules may have an
**action** attribute set to value **include** or **exclude**.

### <a name="ipset"></a>IP Sets

Any IP set referenced by rule objects should be created by
awall. Auxiliary *IP set* objects are used to defined them in awall
policy files. The top-level attribute **ipset** is a dictionary, the
keys of which are IP set names. The values are IP set objects, which
have two mandatory attributes. The attribute named **type**
corresponds to the type argument of the `ipset create`
command. **family** specifies whether the set is for IPv4 or IPv6
addresses, and the possible values are **inet** and **inet6**,
correspondingly.

For bitmap-type IP sets, the **range** attribute specifies the range
of allowed IPv4 addresses. It may be given as a network address or two
addresses separated by the **-** character. It is not necessary to
specify **family** for bitmaps, since the kernel supports only IPv4
bitmaps.

## Command Line Syntax

### Translating Policy Files to Firewall Configuration Files

 **awall translate** \[**-o** | **--output** DIRECTORY\] \[**-V** | **--verify**\]

The `--verify` option makes awall verify the configuration using the
test mode of iptables-restore before overwriting the old files.

Specifying the output directory allows testing awall policies without
overwriting the current iptables and ipset configuration files. By
default, awall generates the configuration to `/etc/iptables` and
`/etc/ipset.d`, which are read by the init scripts.

### Run-Time Configuration of Firewall

 **awall activate** \[**-f** | **--force**\]

This command genereates firewall configuration from the policy files
and enables it. If the user confirms the new configuration by hitting
the Return key within 10 seconds or the `--force` option is used, the
configuration is saved to the files. Otherwise, the old configuration
is restored.

There is also a command for deleting all firewall rules:

 **awall flush**

This command configures the firewall to drop all packets.

### Optional Policies

Optional policies can be enabled or disabled using this command:

 **awall** {**enable** | **disable**} POLICY...

Optional policies can be listed using this command:

 **awall list**

The **enabled** status means that the policy has been enabled by the
user. The **disabled** status means that the policy is not in use. The
**required** status means that the policy has not been enabled by the
user but is in use because it is required by another policy which is
in use.

### Debugging Policies

This command can be used to dump variable, zone, and other definitions
as well as their source policies:

 **awall dump** \[LEVEL\]

The level is an integer in range 0&ndash;5 and defaults to 0. More
information is displayed on higher levels.
