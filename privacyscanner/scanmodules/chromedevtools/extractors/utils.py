from dns import resolver
from dns.exception import DNSException


def get_cname(extractor, qname, rdtype):
    try:
        answer = resolver.query(qname, rdtype)
    except (resolver.NXDOMAIN, resolver.NoAnswer, resolver.NoNameservers):
        return None
    except DNSException as e:
        extractor.logger.warning('Could not get %(rdtype) records for %(qname)s: %(msg)s',
                                 {'qname': qname, 'rdtype': rdtype, 'msg': str(e)})
        return None
    return str(answer.canonical_name) if answer.qname != answer.canonical_name else None


def get_attr(extractor, node_id, attribute):
    attrs = extractor.page.tab.DOM.getAttributes(nodeId=node_id)['attributes']
    attrs = dict(zip(*[iter(attrs)] * 2))
    return attrs.get(attribute)
