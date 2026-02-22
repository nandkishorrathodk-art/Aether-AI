"""
Screenshot Annotation System - IRONCLAW ENHANCEMENT
Draw bounding boxes, labels, highlights, and annotations on images
"""
import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFont
from typing import List, Tuple, Optional, Dict, Any
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Annotation:
    """Annotation element to draw on image."""
    type: str  # "box", "text", "highlight", "arrow", "circle"
    position: Tuple[int, int, int, int]  # (x1, y1, x2, y2) or (x, y, width, height)
    text: Optional[str] = None
    color: Tuple[int, int, int] = (0, 255, 0)  # RGB
    thickness: int = 2
    fill: bool = False
    font_size: int = 16


class ImageAnnotator:
    """
    Annotate images with bounding boxes, text, highlights, etc.
    Useful for creating visual proof-of-concept screenshots.
    """
    
    def __init__(self, font_path: Optional[Path] = None):
        """
        Initialize annotator.
        
        Args:
            font_path: Path to TTF font file (optional)
        """
        self.font_path = font_path
        
        # Predefined colors
        self.colors = {
            "red": (255, 0, 0),
            "green": (0, 255, 0),
            "blue": (0, 0, 255),
            "yellow": (255, 255, 0),
            "cyan": (0, 255, 255),
            "magenta": (255, 0, 255),
            "orange": (255, 165, 0),
            "purple": (128, 0, 128),
            "white": (255, 255, 255),
            "black": (0, 0, 0),
        }
    
    def annotate(self, image: np.ndarray, annotations: List[Annotation]) -> np.ndarray:
        """
        Apply all annotations to image.
        
        Args:
            image: Input image (numpy array)
            annotations: List of annotations to draw
        
        Returns:
            Annotated image
        """
        # Convert to PIL for better text rendering
        pil_image = Image.fromarray(cv2.cvtColor(image, cv2.COLOR_BGR2RGB))
        draw = ImageDraw.Draw(pil_image, "RGBA")
        
        for annotation in annotations:
            if annotation.type == "box":
                self._draw_box(draw, annotation)
            elif annotation.type == "text":
                self._draw_text(draw, annotation)
            elif annotation.type == "highlight":
                self._draw_highlight(draw, annotation)
            elif annotation.type == "arrow":
                self._draw_arrow(pil_image, annotation)
            elif annotation.type == "circle":
                self._draw_circle(draw, annotation)
        
        # Convert back to numpy array
        annotated = cv2.cvtColor(np.array(pil_image), cv2.COLOR_RGB2BGR)
        return annotated
    
    def _draw_box(self, draw: ImageDraw.Draw, annotation: Annotation) -> None:
        """Draw bounding box."""
        x1, y1, x2, y2 = annotation.position
        
        if annotation.fill:
            # Semi-transparent fill
            overlay = Image.new('RGBA', draw.im.size, (0, 0, 0, 0))
            overlay_draw = ImageDraw.Draw(overlay)
            color_with_alpha = annotation.color + (80,)  # 30% opacity
            overlay_draw.rectangle([x1, y1, x2, y2], fill=color_with_alpha)
            draw.im.alpha_composite(overlay)
        
        # Draw box outline
        draw.rectangle(
            [x1, y1, x2, y2],
            outline=annotation.color,
            width=annotation.thickness
        )
        
        # Add label if provided
        if annotation.text:
            self._draw_label(draw, annotation.text, (x1, y1 - 20), annotation.color)
    
    def _draw_text(self, draw: ImageDraw.Draw, annotation: Annotation) -> None:
        """Draw text annotation."""
        x, y, _, _ = annotation.position
        
        try:
            if self.font_path and Path(self.font_path).exists():
                font = ImageFont.truetype(str(self.font_path), annotation.font_size)
            else:
                font = ImageFont.load_default()
        except Exception:
            font = ImageFont.load_default()
        
        # Draw text with background
        if annotation.text:
            bbox = draw.textbbox((x, y), annotation.text, font=font)
            draw.rectangle(bbox, fill=(0, 0, 0, 180))
            draw.text((x, y), annotation.text, fill=annotation.color, font=font)
    
    def _draw_highlight(self, draw: ImageDraw.Draw, annotation: Annotation) -> None:
        """Draw semi-transparent highlight."""
        x1, y1, x2, y2 = annotation.position
        
        # Create semi-transparent overlay
        color_with_alpha = annotation.color + (100,)  # 40% opacity
        draw.rectangle([x1, y1, x2, y2], fill=color_with_alpha)
    
    def _draw_arrow(self, image: Image.Image, annotation: Annotation) -> None:
        """Draw arrow pointing to location."""
        x1, y1, x2, y2 = annotation.position
        
        # Convert to numpy for OpenCV arrow drawing
        np_image = np.array(image)
        cv2.arrowedLine(
            np_image,
            (x1, y1),
            (x2, y2),
            annotation.color,
            annotation.thickness,
            tipLength=0.3
        )
        
        # Convert back to PIL
        image.paste(Image.fromarray(np_image))
    
    def _draw_circle(self, draw: ImageDraw.Draw, annotation: Annotation) -> None:
        """Draw circle annotation."""
        x, y, radius, _ = annotation.position
        
        if annotation.fill:
            draw.ellipse(
                [x - radius, y - radius, x + radius, y + radius],
                fill=annotation.color,
                outline=annotation.color,
                width=annotation.thickness
            )
        else:
            draw.ellipse(
                [x - radius, y - radius, x + radius, y + radius],
                outline=annotation.color,
                width=annotation.thickness
            )
    
    def _draw_label(self, draw: ImageDraw.Draw, text: str, position: Tuple[int, int],
                    color: Tuple[int, int, int], font_size: int = 14) -> None:
        """Draw label with background."""
        x, y = position
        
        try:
            if self.font_path and Path(self.font_path).exists():
                font = ImageFont.truetype(str(self.font_path), font_size)
            else:
                font = ImageFont.load_default()
        except Exception:
            font = ImageFont.load_default()
        
        bbox = draw.textbbox((x, y), text, font=font)
        
        # Add padding
        padding = 4
        bbox = (bbox[0] - padding, bbox[1] - padding, bbox[2] + padding, bbox[3] + padding)
        
        # Draw background
        draw.rectangle(bbox, fill=(0, 0, 0, 200))
        
        # Draw text
        draw.text((x, y), text, fill=color, font=font)
    
    def annotate_ocr_results(self, image: np.ndarray, ocr_results: List[Any],
                            color: str = "green") -> np.ndarray:
        """
        Annotate image with OCR results (bounding boxes + text).
        
        Args:
            image: Input image
            ocr_results: List of OCR results with text and position
            color: Color name or RGB tuple
        
        Returns:
            Annotated image
        """
        annotations = []
        
        color_rgb = self.colors.get(color, (0, 255, 0)) if isinstance(color, str) else color
        
        for result in ocr_results:
            if hasattr(result, 'position') and hasattr(result, 'text'):
                annotations.append(Annotation(
                    type="box",
                    position=result.position,
                    text=result.text,
                    color=color_rgb,
                    thickness=2
                ))
        
        return self.annotate(image, annotations)
    
    def annotate_detections(self, image: np.ndarray, detections: List[Any],
                           color: str = "blue") -> np.ndarray:
        """
        Annotate image with object detection results.
        
        Args:
            image: Input image
            detections: List of detected objects with bbox and label
            color: Color name or RGB tuple
        
        Returns:
            Annotated image
        """
        annotations = []
        
        color_rgb = self.colors.get(color, (0, 0, 255)) if isinstance(color, str) else color
        
        for detection in detections:
            if hasattr(detection, 'bbox') and hasattr(detection, 'label'):
                label_text = f"{detection.label}"
                if hasattr(detection, 'confidence'):
                    label_text += f" ({detection.confidence:.2f})"
                
                annotations.append(Annotation(
                    type="box",
                    position=detection.bbox,
                    text=label_text,
                    color=color_rgb,
                    thickness=3
                ))
        
        return self.annotate(image, annotations)
    
    def highlight_region(self, image: np.ndarray, region: Tuple[int, int, int, int],
                        color: str = "yellow", text: Optional[str] = None) -> np.ndarray:
        """
        Highlight a region of interest.
        
        Args:
            image: Input image
            region: Region to highlight (x1, y1, x2, y2)
            color: Color name or RGB tuple
            text: Optional label text
        
        Returns:
            Annotated image
        """
        color_rgb = self.colors.get(color, (255, 255, 0)) if isinstance(color, str) else color
        
        annotations = [
            Annotation(
                type="highlight",
                position=region,
                color=color_rgb
            ),
            Annotation(
                type="box",
                position=region,
                text=text,
                color=color_rgb,
                thickness=3
            )
        ]
        
        return self.annotate(image, annotations)
    
    def add_arrow(self, image: np.ndarray, start: Tuple[int, int],
                 end: Tuple[int, int], color: str = "red",
                 text: Optional[str] = None) -> np.ndarray:
        """
        Add arrow pointing from start to end.
        
        Args:
            image: Input image
            start: Starting point (x, y)
            end: Ending point (x, y)
            color: Color name or RGB tuple
            text: Optional label
        
        Returns:
            Annotated image
        """
        color_rgb = self.colors.get(color, (255, 0, 0)) if isinstance(color, str) else color
        
        annotations = [
            Annotation(
                type="arrow",
                position=(*start, *end),
                color=color_rgb,
                thickness=3
            )
        ]
        
        if text:
            # Add text near the arrow
            mid_x = (start[0] + end[0]) // 2
            mid_y = (start[1] + end[1]) // 2
            annotations.append(Annotation(
                type="text",
                position=(mid_x, mid_y, 0, 0),
                text=text,
                color=color_rgb,
                font_size=16
            ))
        
        return self.annotate(image, annotations)
    
    def save_annotated(self, image: np.ndarray, path: Path) -> Path:
        """Save annotated image to file."""
        cv2.imwrite(str(path), image)
        return path


# Global instance
_annotator: Optional[ImageAnnotator] = None


def get_annotator(font_path: Optional[Path] = None) -> ImageAnnotator:
    """Get global ImageAnnotator instance."""
    global _annotator
    if _annotator is None:
        _annotator = ImageAnnotator(font_path)
    return _annotator
