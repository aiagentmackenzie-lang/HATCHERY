/**
 * Process-tree parsing tests.
 *
 * Run with `npm test` (after `npm run build`) — uses Node's built-in test
 * runner so there is no new dependency. This covers a real fix: the tree used
 * to be grouped by PID because the `clone(...) = <child pid>` return value was
 * never read, so the dashboard's Process Tree showed a flat list of unrelated
 * PIDs. Regression: without the parent map, these tests fail.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { buildProcessTree } from '../dist/routes/analysis.js';

test('clone return value becomes a real parent/child edge', () => {
  const events = [
    { pid: 48, syscall_name: 'execve', args: '"/hatchery/sample/x"', return_value: '0', timestamp: 't0' },
    { pid: 48, syscall_name: 'clone', args: 'child_stack=0x0', return_value: '49', timestamp: 't1' },
    { pid: 49, syscall_name: 'execve', args: '"/usr/bin/id"', return_value: '0', timestamp: 't2' },
  ];
  const tree = buildProcessTree(events);

  assert.equal(tree.pid, 48);
  assert.equal(tree.children.length, 1);
  assert.equal(tree.children[0].pid, 49);
});

test('nested clones produce nested children', () => {
  const events = [
    { pid: 10, syscall_name: 'clone', args: 'x', return_value: '11', timestamp: 't0' },
    { pid: 11, syscall_name: 'clone', args: 'x', return_value: '12', timestamp: 't1' },
    { pid: 12, syscall_name: 'execve', args: '"/bin/sh"', return_value: '0', timestamp: 't2' },
  ];
  const tree = buildProcessTree(events);

  assert.equal(tree.pid, 10);
  assert.equal(tree.children[0].pid, 11);
  assert.equal(tree.children[0].children[0].pid, 12);
});

test('failed clone (negative return) creates no child', () => {
  const events = [
    { pid: 5, syscall_name: 'clone', args: 'x', return_value: '-1 EAGAIN (Resource temporarily unavailable)', timestamp: 't0' },
  ];
  const tree = buildProcessTree(events);

  assert.equal(tree.pid, 5);
  assert.deepEqual(tree.children, []);
});

test('non-clone events never create parent edges', () => {
  const events = [
    { pid: 5, syscall_name: 'execve', args: 'x', return_value: '7', timestamp: 't0' },
    { pid: 9, syscall_name: 'openat', args: 'x', return_value: '3', timestamp: 't1' },
  ];
  const tree = buildProcessTree(events);

  assert.equal(tree.pid, 5);
  assert.deepEqual(tree.children, []);
});

test('empty input yields an empty root, not a crash', () => {
  const tree = buildProcessTree([]);
  assert.deepEqual(tree, { pid: 0, children: [], syscalls: [] });
});
