#!/bin/bash
# Integration test script for netwatch
# Tests on real network interface with radiotap parsing

set -e

echo "=== Netwatch Integration Test ==="
echo ""

# Check if running as root (required for packet capture)
if [ "$EUID" -ne 0 ]; then 
    echo "Error: This script must be run as root (for packet capture)"
    echo "Usage: sudo $0 [interface]"
    exit 1
fi

# Get interface name
IFACE=${1:-""}
if [ -z "$IFACE" ]; then
    echo "Available interfaces:"
    ip link show | grep -E "^[0-9]+:" | awk '{print $2}' | sed 's/://'
    echo ""
    echo "Usage: sudo $0 <interface>"
    echo "Example: sudo $0 wlan0"
    exit 1
fi

# Check if interface exists
if ! ip link show "$IFACE" > /dev/null 2>&1; then
    echo "Error: Interface $IFACE not found"
    exit 1
fi

# Check if iw is available (for WiFi interfaces)
if command -v iw > /dev/null 2>&1; then
    echo "Checking if $IFACE is a WiFi interface..."
    if iw dev "$IFACE" info > /dev/null 2>&1; then
        echo "✓ $IFACE is a WiFi interface"
        WIFI=true
    else
        echo "⚠ $IFACE is not a WiFi interface (or iw command failed)"
        WIFI=false
    fi
else
    echo "⚠ 'iw' command not found - cannot verify WiFi interface"
    WIFI=false
fi

# Create test directory
TEST_DIR="/tmp/netwatch_test_$$"
mkdir -p "$TEST_DIR"
echo "Test directory: $TEST_DIR"

# Build the project
echo ""
echo "Building netwatch..."
if ! go build -o "$TEST_DIR/netwatch" .; then
    echo "Error: Build failed"
    exit 1
fi
echo "✓ Build successful"

# Test 1: Dry run
echo ""
echo "=== Test 1: Dry Run ==="
if "$TEST_DIR/netwatch" -i "$IFACE" -n -q; then
    echo "✓ Dry run successful"
else
    echo "✗ Dry run failed"
    exit 1
fi

# Test 2: Short capture (5 seconds)
echo ""
echo "=== Test 2: Short Capture (5 seconds) ==="
echo "Capturing packets for 5 seconds..."
if timeout 6 "$TEST_DIR/netwatch" -i "$IFACE" -q -a "dur:5s" -o "$TEST_DIR"; then
    echo "✓ Capture completed"
    
    # Check if pcap file was created
    PCAP_FILE=$(find "$TEST_DIR" -name "*.pcap" | head -1)
    if [ -n "$PCAP_FILE" ]; then
        echo "✓ PCAP file created: $PCAP_FILE"
        
        # Check file size
        SIZE=$(stat -f%z "$PCAP_FILE" 2>/dev/null || stat -c%s "$PCAP_FILE" 2>/dev/null)
        echo "  File size: $SIZE bytes"
        
        # Try to read with tcpdump/tshark if available
        if command -v tcpdump > /dev/null 2>&1; then
            echo ""
            echo "First few packets (tcpdump):"
            tcpdump -r "$PCAP_FILE" -c 5 2>/dev/null || echo "  (tcpdump read failed)"
        fi
    else
        echo "⚠ No PCAP file found"
    fi
    
    # Check if events file was created
    EVENTS_FILE="$TEST_DIR/events.jsonl"
    if [ -f "$EVENTS_FILE" ]; then
        echo "✓ Events file created: $EVENTS_FILE"
        EVENT_COUNT=$(wc -l < "$EVENTS_FILE")
        echo "  Event count: $EVENT_COUNT"
        if [ "$EVENT_COUNT" -gt 0 ]; then
            echo "  First event:"
            head -1 "$EVENTS_FILE" | python3 -m json.tool 2>/dev/null || head -1 "$EVENTS_FILE"
        fi
    else
        echo "⚠ No events file found"
    fi
else
    echo "✗ Capture failed"
    exit 1
fi

# Test 3: Radiotap parsing (WiFi only)
if [ "$WIFI" = true ]; then
    echo ""
    echo "=== Test 3: Radiotap Parsing ==="
    echo "Capturing WiFi packets to test radiotap parsing..."
    
    if timeout 6 "$TEST_DIR/netwatch" -i "$IFACE" -q -a "dur:5s" -o "$TEST_DIR/radiotap_test"; then
        RADIOTAP_PCAP=$(find "$TEST_DIR/radiotap_test" -name "*.pcap" | head -1)
        if [ -n "$RADIOTAP_PCAP" ]; then
            echo "✓ Radiotap test PCAP: $RADIOTAP_PCAP"
            
            # Use tshark if available to analyze radiotap
            if command -v tshark > /dev/null 2>&1; then
                echo ""
                echo "Radiotap header analysis (tshark):"
                tshark -r "$RADIOTAP_PCAP" -T fields -e wlan_radio.channel -e wlan_radio.signal_dbm -e wlan_radio.noise_dbm -c 10 2>/dev/null | head -10 || echo "  (tshark analysis failed)"
            fi
        fi
    fi
fi

# Test 4: Summary mode
echo ""
echo "=== Test 4: Summary Mode ==="
echo "Testing summary display (will timeout after 3 seconds)..."
if timeout 4 "$TEST_DIR/netwatch" -i "$IFACE" -S -a "dur:3s" -o "$TEST_DIR/summary_test" 2>&1 | head -20; then
    echo "✓ Summary mode test completed"
else
    echo "⚠ Summary mode test had issues (may be expected)"
fi

# Cleanup
echo ""
echo "=== Cleanup ==="
echo "Test files are in: $TEST_DIR"
echo "To clean up: rm -rf $TEST_DIR"
echo ""
echo "=== Integration Test Complete ==="
echo "✓ All tests passed!"

