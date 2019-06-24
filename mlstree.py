import logging

log = logging.getLogger('MLS')


class Node:
    def __init__(self, label=None):
        self.left = None
        self.right = None
        self.parent = None
        self._label = label

    def direct_path(self):
        if self.parent is not None:
            return [self] + self.parent.direct_path()
        return []

    def sibling(self):
        if self.parent is not None:
            if self.parent.left is self:
                return self.parent.right
            else:
                return self.parent.left
        return None

    def height(self):
        if self.left is None:
            return 1
        return 1 + self.left.height()

    def copath(self):
        dp = self.direct_path()
        return [n.sibling() for n in self.direct_path()]

    def full(self):
        if self.left is not None and self.right is not None:
            return True
        return False

    def full_subtree(self):
        if self.left is None and self.right is None:
            return True
        if self.left is None or not self.left.full_subtree():
            return False
        if self.right is None or not self.right.full_subtree():
            return False
        return True

    def frontier(self):
        if self.full_subtree():
            return [self]
        f = []
        if self.left is not None:
            f = f + self.left.frontier()
        if self.right is not None:
            f = f + self.right.frontier()
        return f

    def add_node(self, node):
        log.debug("Adding label %s to %s", node.label(), self.label())
        if self._label is None:
            log.debug("Not a leaf")
            if self.left is None:
                log.debug("No LHS")
                self.left = node
                self.left.parent = self
                return self
            if not self.left.full_subtree():
                log.debug("LHS is not full")
                self.left.add_node(node)
                return self
            if self.right is None:
                log.debug("No RHS")
                h = self.left.height()
                if h == 1:
                    self.right = node
                    self.right.parent = None
                else:
                    self.right = Node()
                    self.right.parent = self
                    nn = self.right
                    h -= 2
                    while h > 0:
                        nn.left = Node()
                        nn.left.parent = nn
                        nn = nn.left
                        h -= 1
                    nn.left = node
                    node.parent = nn
                return self
            if not self.right.full_subtree():
                log.debug("RHS is not full")
                self.right.add_node(node)
                return self
        log.debug("Parent insertion")
        self.parent = Node()
        self.parent.left = self
        return self.parent.add_node(node)

    def label(self, really=False):
        if self._label is not None:
            return self._label
        l = ''
        if self.left:
            l = self.left.label(True)
        r = ''
        if self.right:
            r = self.right.label(True)
        if not really and self.right is None:
            return ''
        return l + r

    def all_nodes(self):
        if self.left:
            for n in self.left.all_nodes():
                yield n
        if self._label or self.full():
            yield self
        if self.right:
            for n in self.right.all_nodes():
                yield n

    def leaf_nodes(self):
        if self.left:
            for n in self.left.leaf_nodes():
                yield n
        if self._label:
            yield self
        if self.right:
            for n in self.right.leaf_nodes():
                yield n


logging.basicConfig(level=logging.DEBUG)

data = 'ABCDEFG'
nodes = dict()

tree = None
for c in data:
    nodes[c] = Node(c)
    if tree:
        tree = tree.add_node(nodes[c])
    else:
        tree = nodes[c]

print("Direct path of C", repr([n.label() for n in nodes['C'].direct_path()]))
print("Copath of C", repr([n.label() for n in nodes['C'].copath()]))
print("Frontier of tree", repr([n.label() for n in tree.frontier()]))
print("All nodes", repr([n.label() for n in tree.all_nodes()]))
print("Leaf nodes", repr([n.label() for n in tree.leaf_nodes()]))
