"""
LED Status Indicator for IDS
Controls RGB status LEDs for visual feedback
Auto-detects if LEDs are connected
"""

import time
from threading import Thread

# Try to import RPi.GPIO
try:
    import RPi.GPIO as GPIO
    GPIO_AVAILABLE = True
except (ImportError, RuntimeError):
    GPIO_AVAILABLE = False

# GPIO Pin Configuration (BCM numbering)
GREEN_LED = 17   # Normal operation
YELLOW_LED = 27  # Detection/Warning  
RED_LED = 22     # Attack blocked


class LEDController:
    """Controls status LEDs for IDS visual feedback."""
    
    def __init__(self):
        """Initialize GPIO pins for LED control."""
        self.enabled = False
        
        # Check if GPIO is available
        if not GPIO_AVAILABLE:
            print("[WARN] RPi.GPIO not available - LED indicators disabled")
            print("[INFO] Running without LED support")
            return
        
        try:
            GPIO.setmode(GPIO.BCM)
            GPIO.setwarnings(False)
            
            # Setup pins as outputs
            GPIO.setup(GREEN_LED, GPIO.OUT)
            GPIO.setup(YELLOW_LED, GPIO.OUT)
            GPIO.setup(RED_LED, GPIO.OUT)
            
            # Test if LEDs respond (set all low first)
            GPIO.output(GREEN_LED, GPIO.LOW)
            GPIO.output(YELLOW_LED, GPIO.LOW)
            GPIO.output(RED_LED, GPIO.LOW)
            
            # Quick test - flash green
            GPIO.output(GREEN_LED, GPIO.HIGH)
            time.sleep(0.1)
            GPIO.output(GREEN_LED, GPIO.LOW)
            
            self.enabled = True
            print("[*] ✓ LED Controller initialized - Hardware detected")
            
        except Exception as e:
            print(f"[WARN] LED initialization failed: {e}")
            print("[INFO] Running without LED support")
            self.enabled = False
    
    def set_normal(self):
        """Green LED on - Normal operation."""
        if not self.enabled:
            return
        try:
            GPIO.output(GREEN_LED, GPIO.HIGH)
            GPIO.output(YELLOW_LED, GPIO.LOW)
            GPIO.output(RED_LED, GPIO.LOW)
        except:
            pass
    
    def set_detecting(self):
        """Yellow LED on - Attack detected."""
        if not self.enabled:
            return
        try:
            GPIO.output(GREEN_LED, GPIO.LOW)
            GPIO.output(YELLOW_LED, GPIO.HIGH)
            GPIO.output(RED_LED, GPIO.LOW)
        except:
            pass
    
    def set_blocked(self):
        """Red LED on - Attacker blocked."""
        if not self.enabled:
            return
        try:
            GPIO.output(GREEN_LED, GPIO.LOW)
            GPIO.output(YELLOW_LED, GPIO.LOW)
            GPIO.output(RED_LED, GPIO.HIGH)
        except:
            pass
    
    def flash_red(self, times=3, duration=0.5):
        """Flash red LED to indicate blocking."""
        if not self.enabled:
            return
        try:
            for _ in range(times):
                GPIO.output(RED_LED, GPIO.HIGH)
                time.sleep(duration)
                GPIO.output(RED_LED, GPIO.LOW)
                time.sleep(duration)
            # Return to blocked state
            self.set_blocked()
        except:
            pass
    
    def flash_yellow(self, times=2, duration=0.3):
        """Flash yellow LED to indicate detection."""
        if not self.enabled:
            return
        try:
            for _ in range(times):
                GPIO.output(YELLOW_LED, GPIO.HIGH)
                time.sleep(duration)
                GPIO.output(YELLOW_LED, GPIO.LOW)
                time.sleep(duration)
        except:
            pass
    
    def all_off(self):
        """Turn off all LEDs."""
        if not self.enabled:
            return
        try:
            GPIO.output(GREEN_LED, GPIO.LOW)
            GPIO.output(YELLOW_LED, GPIO.LOW)
            GPIO.output(RED_LED, GPIO.LOW)
        except:
            pass
    
    def startup_sequence(self):
        """LED startup animation."""
        if not self.enabled:
            return
        try:
            self.all_off()
            time.sleep(0.3)
            GPIO.output(RED_LED, GPIO.HIGH)
            time.sleep(0.3)
            GPIO.output(YELLOW_LED, GPIO.HIGH)
            time.sleep(0.3)
            GPIO.output(GREEN_LED, GPIO.HIGH)
            time.sleep(0.5)
            self.set_normal()
        except:
            pass
    
    def cleanup(self):
        """Cleanup GPIO on shutdown."""
        if not self.enabled:
            return
        try:
            self.all_off()
            GPIO.cleanup()
            print("[*] LED Controller cleaned up")
        except:
            pass


# Test function
if __name__ == "__main__":
    print("=" * 50)
    print("LED Controller Test")
    print("=" * 50)
    
    led = LEDController()
    
    if not led.enabled:
        print("\n[!] LED hardware not detected or not available")
        print("[!] Make sure:")
        print("    1. Running on Raspberry Pi")
        print("    2. RPi.GPIO is installed: sudo apt install python3-rpi.gpio")
        print("    3. LEDs are connected to GPIO pins 17, 27, 22")
        print("    4. Running with sudo")
        exit(1)
    
    print("\n[*] LED hardware detected - Starting test sequence...")
    
    print("\n[1/6] Startup sequence...")
    led.startup_sequence()
    time.sleep(1)
    
    print("[2/6] Normal state (Green)")
    led.set_normal()
    time.sleep(2)
    
    print("[3/6] Detecting state (Yellow)")
    led.set_detecting()
    time.sleep(2)
    
    print("[4/6] Blocked state (Red)")
    led.set_blocked()
    time.sleep(2)
    
    print("[5/6] Flash red (blocking action)")
    led.flash_red()
    time.sleep(1)
    
    print("[6/6] Flash yellow (warning)")
    led.flash_yellow()
    time.sleep(1)
    
    print("\n[*] Returning to normal state")
    led.set_normal()
    time.sleep(1)
    
    led.cleanup()
    print("\n[✓] Test complete!")
    print("=" * 50)
