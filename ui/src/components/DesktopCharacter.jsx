import React, { useState, useEffect } from 'react';
import './DesktopCharacter.css';

const DesktopCharacter = ({ isListening, isSpeaking, transcript, responseText, onInteraction }) => {
    const [animationState, setAnimationState] = useState('idle');
    const [menuOpen, setMenuOpen] = useState(false);
    const [menuPosition, setMenuPosition] = useState({ x: 0, y: 0 });

    // Drag state
    const [position, setPosition] = useState({ x: window.innerWidth - 150, y: window.innerHeight - 200 });
    const [dragging, setDragging] = useState(false);
    const [offset, setOffset] = useState({ x: 0, y: 0 });
    const characterRef = useRef(null);

    useEffect(() => {
        if (isSpeaking) {
            setAnimationState('speaking');
        } else if (isListening) {
            setAnimationState('listening');
        } else {
            setAnimationState('idle');
        }
    }, [isListening, isSpeaking]);

    const handleMouseDown = (e) => {
        if (e.button !== 0) return; // Only drag on left click
        setDragging(true);
        const rect = characterRef.current.getBoundingClientRect();
        setOffset({
            x: e.clientX - rect.left,
            y: e.clientY - rect.top,
        });
    };

    const handleMouseMove = (e) => {
        if (!dragging) return;
        setPosition({
            x: e.clientX - offset.x,
            y: e.clientY - offset.y,
        });
    };

    const handleMouseUp = () => {
        setDragging(false);
    };

    useEffect(() => {
        if (dragging) {
            window.addEventListener('mousemove', handleMouseMove);
            window.addEventListener('mouseup', handleMouseUp);
        } else {
            window.removeEventListener('mousemove', handleMouseMove);
            window.removeEventListener('mouseup', handleMouseUp);
        }
        return () => {
            window.removeEventListener('mousemove', handleMouseMove);
            window.removeEventListener('mouseup', handleMouseUp);
        };
    }, [dragging, offset]);

    const handleCharacterClick = () => {
        if (menuOpen) {
            setMenuOpen(false);
            return;
        }
        // Trigger parent interaction handler (voice command)
        if (onInteraction) {
            onInteraction();
        }
        setAnimationState('listening');
    };

    const handleContextMenu = (e) => {
        e.preventDefault();
        setMenuOpen(true);
        // Menu position relative to window
        setMenuPosition({ x: e.clientX, y: e.clientY });
    };

    return (
        <div
            ref={characterRef}
            className={`character-container ${animationState}`}
            onContextMenu={handleContextMenu}
            onMouseDown={handleMouseDown}
            style={{
                position: 'fixed',
                left: `${position.x}px`,
                top: `${position.y}px`,
                width: '150px',
                height: 'auto',
                cursor: dragging ? 'grabbing' : 'grab',
                zIndex: 9999
            }}
        >
            <div
                className="character-image-wrapper"
                onClick={handleCharacterClick}
            >
                <img
                    src={process.env.PUBLIC_URL + '/character.png'}
                    alt="Desktop Character"
                    className="character-img"
                    onError={(e) => { e.target.style.display = 'none'; document.getElementById('placeholder-text').style.display = 'block'; }}
                    style={{ pointerEvents: 'none' }} // Prevent native image drag
                />
                <div id="placeholder-text" style={{ display: 'none', color: 'white', textAlign: 'center', marginTop: '50px' }}>
                    <h3>Character Image Not Found</h3>
                    <p>Please place 'character.png' in the ui/public folder.</p>
                </div>
            </div>

            {/* Speech Bubble / Status Indicator */}
            {(transcript || responseText || isListening) && (
                <div className="speech-bubble">
                    {isListening && !transcript && <span className="listening-indicator">Listening...</span>}
                    {transcript && <span className="user-text">Recieved: "{transcript}"</span>}
                    {isSpeaking && responseText && <span className="ai-text">{responseText}</span>}
                </div>
            )}

            {/* Context Menu */}
            {menuOpen && (
                <div
                    className="context-menu"
                    style={{ top: menuPosition.y, left: menuPosition.x }}
                    onClick={() => setMenuOpen(false)}
                >
                    <div className="menu-item">Talk to Aether</div>
                    <div className="menu-item">Hide Character</div>
                    <div className="menu-item">Settings</div>
                </div>
            )}

            {/* Visual Effects for States */}
            <div className="aura-effect"></div>
        </div>
    );
};

export default DesktopCharacter;
