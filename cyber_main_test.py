"""
Test Script for CyberMain UI
"""

import pygame
import sys
import os

# Initialize pygame
pygame.init()

# Set up display
screen = pygame.display.set_mode((800, 600))
pygame.display.set_caption("CyberAI Security Suite")

# Set up font
font = pygame.font.SysFont("Arial", 24)

clock = pygame.time.Clock()

def test_basic_functionality():
    """Test that the basic UI loop works"""
    running = True
    while running and clock.get_fps() > 0:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False
        
        # Fill screen with dark background
        screen.fill((10, 10, 30))
        
        # Write test message
        text = font.render("CyberAI Interface Test - SUCCESS", True, (0, 255, 0))
        screen.blit(text, (100, 250))
        
        # Draw progress indicator
        pygame.draw.circle(screen, (0, 255, 0), (400, 300), 50, width=4)
        
        pygame.display.flip()
        clock.tick(60)
    
    pygame.quit()

if __name__ == "__main__":
    test_basic_functionality()