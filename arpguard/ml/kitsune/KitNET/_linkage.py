# [arpguard] Minimal pure-NumPy stand-in for the two SciPy functions corClust
# uses (single-linkage `linkage` on a condensed distance vector, and `to_tree`).
# It follows SciPy's own algorithm (Prim's MST, stable sort by distance, then
# union-find relabelling), so it returns the same dendrogram, ties included.
# This keeps SciPy (~100 MB) out of the serverless bundle.
import numpy as np


def _condensed_index(n, i, j):
    if i > j:
        i, j = j, i
    return n * i - (i * (i + 1) // 2) + (j - i - 1)


def linkage(y):
    y = np.asarray(y, dtype=float)
    n = int(np.ceil(np.sqrt(y.size * 2)))
    if n * (n - 1) // 2 != y.size:
        raise ValueError("expected a condensed distance vector")
    Z = np.empty((n - 1, 4))
    merged = np.zeros(n, dtype=bool)
    D = np.full(n, np.inf)
    x = 0
    y_node = 0
    for k in range(n - 1):
        current_min = np.inf
        merged[x] = True
        for i in range(n):
            if merged[i]:
                continue
            dist = y[_condensed_index(n, x, i)]
            if D[i] > dist:
                D[i] = dist
            if D[i] < current_min:
                y_node = i
                current_min = D[i]
        Z[k, 0] = x
        Z[k, 1] = y_node
        Z[k, 2] = current_min
        x = y_node
    Z = Z[np.argsort(Z[:, 2], kind="mergesort")]
    _label(Z, n)
    return Z


def _label(Z, n):
    parent = np.arange(2 * n - 1)
    size = np.ones(2 * n - 1, dtype=int)
    next_label = n

    def find(x):
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:
            parent[x], x = root, parent[x]
        return root

    for i in range(n - 1):
        xr, yr = find(int(Z[i, 0])), find(int(Z[i, 1]))
        Z[i, 0], Z[i, 1] = (xr, yr) if xr < yr else (yr, xr)
        parent[xr] = parent[yr] = next_label
        size[next_label] = size[xr] + size[yr]
        Z[i, 3] = size[next_label]
        next_label += 1


class ClusterNode:
    def __init__(self, id, left=None, right=None, dist=0.0, count=1):
        self.id = id
        self.left = left
        self.right = right
        self.dist = dist
        self.count = count if left is None else left.count + right.count

    def get_left(self):
        return self.left

    def get_right(self):
        return self.right

    def pre_order(self):
        out, stack = [], [self]
        while stack:
            nd = stack.pop()
            if nd.left is None:
                out.append(nd.id)
            else:
                stack.append(nd.right)
                stack.append(nd.left)
        return out


def to_tree(Z):
    Z = np.asarray(Z)
    n = Z.shape[0] + 1
    nodes = [ClusterNode(i) for i in range(n)] + [None] * (n - 1)
    for i in range(n - 1):
        fi, fj = int(Z[i, 0]), int(Z[i, 1])
        nodes[n + i] = ClusterNode(n + i, nodes[fi], nodes[fj], Z[i, 2])
    return nodes[2 * n - 2]
