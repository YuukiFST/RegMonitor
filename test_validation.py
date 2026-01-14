from app import normalize_path, is_child_of, check_if_child_of_existing, find_children_of, is_exact_duplicate

# Test 1: normalize_path
print('=== Test normalize_path ===')
assert normalize_path('HKCU\\Software\\Thorium\\') == 'hkcu\\software\\thorium'
assert normalize_path('  HKCU\\Software\\Thorium  ') == 'hkcu\\software\\thorium'
print('PASS: normalize_path')

# Test 2: is_child_of
print('=== Test is_child_of ===')
assert is_child_of('HKCU\\Software\\Thorium\\StabilityMetrics', 'HKCU\\Software\\Thorium') == True
assert is_child_of('HKCU\\Software\\Thorium\\Network\\Config', 'HKCU\\Software\\Thorium') == True
assert is_child_of('HKCU\\Software\\ThoriumBackup', 'HKCU\\Software\\Thorium') == False
assert is_child_of('HKCU\\Software\\Thorium', 'HKCU\\Software\\Thorium') == False
print('PASS: is_child_of')

# Test 3: check_if_child_of_existing
print('=== Test check_if_child_of_existing ===')
existing = ['HKCU\\Software\\Thorium', 'HKCU\\Software\\Chrome']
is_child, parent = check_if_child_of_existing('HKCU\\Software\\Thorium\\Config', existing)
assert is_child == True
assert parent == 'HKCU\\Software\\Thorium'

is_child, parent = check_if_child_of_existing('HKCU\\Software\\Firefox', existing)
assert is_child == False
assert parent == None
print('PASS: check_if_child_of_existing')

# Test 4: find_children_of
print('=== Test find_children_of ===')
existing = ['HKCU\\Software\\Thorium\\StabilityMetrics', 'HKCU\\Software\\Thorium\\Network', 'HKCU\\Software\\Chrome']
children = find_children_of('HKCU\\Software\\Thorium', existing)
assert len(children) == 2
assert 'HKCU\\Software\\Thorium\\StabilityMetrics' in children
assert 'HKCU\\Software\\Thorium\\Network' in children
print('PASS: find_children_of')

# Test 5: is_exact_duplicate
print('=== Test is_exact_duplicate ===')
existing = ['HKCU\\Software\\Thorium', 'HKCU\\Software\\Chrome']
assert is_exact_duplicate('HKCU\\Software\\Thorium', existing) == True
assert is_exact_duplicate('hkcu\\software\\thorium', existing) == True
assert is_exact_duplicate('HKCU\\Software\\Firefox', existing) == False
print('PASS: is_exact_duplicate')

# Test 6: Similar names (false positive prevention)
print('=== Test false positive prevention ===')
existing = ['HKCU\\Software\\Chrome']
children = find_children_of('HKCU\\Software\\Chrome', existing)
assert len(children) == 0
is_child, _ = check_if_child_of_existing('HKCU\\Software\\ChromeExtensions', existing)
assert is_child == False
print('PASS: false positive prevention')

print('')
print('=== ALL TESTS PASSED ===')
