import cv2 as cv
import numpy as np
import os
import pyautogui
import time
from vision import Vision
from windowcapture import WindowCapture
from pywinauto.keyboard import send_keys
import pydirectinput


# Change the working directory to the folder this script is in.
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Initialize the WindowCapture class
wincap = WindowCapture('Hero Plus')

# Load the template image of the mineral and initialize the Vision class
vision_item_mineral = Vision('item.jpg')

##items to drop
vision_00 = Vision('items/adamantine.jpg')
vision_01 = Vision('items/amethyst.jpg')
vision_02 = Vision('items/azure.jpg')
vision_03 = Vision('items/black_coal.jpg')
vision_04 = Vision('items/carbuncle.jpg')
vision_05 = Vision('items/citrine.jpg')
vision_06 = Vision('items/citrine_xtall.jpg')
vision_07 = Vision('items/conf_xtall.jpg')
vision_08 = Vision('items/emerald.jpg')
vision_09 = Vision('items/emerald_xtall.jpg')
vision_10 = Vision('items/garnet.jpg')
vision_11 = Vision('items/garnet_xtall.jpg')
vision_12 = Vision('items/gold_ore.jpg')
vision_13 = Vision('items/iron_ore.jpg')
vision_14 = Vision('items/jadeite_xtall.jpg')
vision_15 = Vision('items/natural_gem.jpg')
vision_16 = Vision('items/opal_xtall.jpg')
vision_17 = Vision('items/para_xtall.jpg')
vision_18 = Vision('items/plain_rock.jpg')
vision_19 = Vision('items/poison_xtall.jpg')
vision_20 = Vision('items/ruby.jpg')
vision_21 = Vision('items/silver_ore.jpg')
vision_24 = Vision('items/jadeite_ball.jpg')
vision_25 = Vision('items/garnet_ball.jpg')
vision_26 = Vision('items/citrine_ball.jpg')
vision_27 = Vision('items/gs.jpg')
vision_28 = Vision('items/psl.jpg')
# Initialize the window capture
screen = pyautogui.getWindowsWithTitle("Hero Plus")[0]
x, y, width, height = screen.left, screen.top, screen.width, screen.height

# Move the mouse to the center of the window
center_x = x + width / 2
center_y = y + height / 2
pyautogui.moveTo(center_x, center_y)
pyautogui.click()

opened = 0

def click(xx,yy):
    pydirectinput.moveTo(xx, yy)
    pyautogui.mouseDown()
    time.sleep(0.1)
    pyautogui.mouseUp()
    

def clickright(xx,yy):
    pydirectinput.moveTo(xx, yy)
    pyautogui.mouseDown(button='right')
    time.sleep(0.1)
    pyautogui.mouseUp(button='right')

    
def findItem():
    global opened
    screenshot = wincap.get_screenshot()
    points = vision_item_mineral.find(screenshot, 0.7, '')
    
    if len(points) > 0:
        item_x, item_y = points[0][0] + x+10, points[0][1] + y +25 
        clickright(item_x, item_y)
        print("Item Opened")
        opened += 1
        if (opened > 150):
            arrange()
            opened = 0
   
def arrange():
    vision_arrange = Vision('arrange.jpg')
    screenshot = wincap.get_screenshot()
    points = vision_arrange.find(screenshot, 0.7, '')
    
    if len(points) > 0:
        item_x, item_y = points[0][0] + x+10, points[0][1] + y +25
        click(item_x, item_y)

    time.sleep(0.1)


def deleteItem(xx,yy):
    

    click(xx,yy)
    time.sleep(0.1)
    click(xx-400,yy)
    time.sleep(0.1)
    
    vision_arrange = Vision('confirm.jpg')
    screenshot = wincap.get_screenshot()
    points = vision_arrange.find(screenshot, 0.93, '')
    
    if len(points) > 0:
        item_x, item_y = points[0][0] + x+10, points[0][1] + y +25
        click(item_x, item_y)


    
   
 
def findDeletableItem():
    pydirectinput.moveTo(x+100, y+100)
    visions = [vision_00, vision_01, vision_02, vision_03, vision_04, vision_05, vision_06, vision_07, vision_08,
               vision_09, vision_10, vision_11, vision_12, vision_13, vision_14, vision_15, vision_16, vision_17,
               vision_18, vision_19, vision_20, vision_21, vision_24, vision_25, vision_26, vision_27, vision_28]

    screenshot = wincap.get_screenshot()

    for vision in visions:
        points = vision.find(screenshot, 0.705, '')

        if len(points) > 0:
            item_x, item_y = points[0][0] + x+10, points[0][1] + y +25
            deleteItem(item_x,item_y)
            
    

while True:
    findItem()
    findDeletableItem()
    
