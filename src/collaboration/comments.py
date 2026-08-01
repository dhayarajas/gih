"""
Ghost Identity Hunter - Collaboration Module

PURPOSE:
--------
Provide collaboration features for investigations, including comments,
annotations, and team collaboration capabilities.

FUNCTIONALITY:
--------------
- Add comments to investigations and artifacts
- Retrieve comments with threading support
- Annotation system for findings
- Comment history and audit trail
- User attribution for comments

USAGE EXAMPLES:
--------------
# Add a comment
from src.collaboration.comments import CommentManager

manager = CommentManager()
manager.add_comment(investigation_id, "This needs further investigation")

# Get comments for an investigation
comments = manager.get_investigation_comments(investigation_id)

DEPENDENCIES:
-------------
- sqlite3: Database operations
- datetime: Date/time handling
- dataclasses: Data structures
- typing: Type hints
- logging: Logging

AUTHOR:
-------
Ghost Identity Hunter Team
CSCD Group 2 - Capstone Project

VERSION:
--------
1.0 - Initial implementation
"""

import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from src.storage.database import get_connection

logger = logging.getLogger(__name__)


@dataclass
class Comment:
    """Represents a comment on an investigation or artifact."""
    comment_id: str
    investigation_id: str
    artifact_id: Optional[str]
    author: str
    content: str
    created_at: str
    updated_at: Optional[str] = None
    parent_id: Optional[str] = None  # For threaded comments
    comment_type: str = "general"  # general, annotation, question, etc.


class CommentManager:
    """Manage comments and annotations for investigations."""
    
    def __init__(self, db_path: Optional[str] = None):
        """Initialize comment manager."""
        self.db_path = db_path
        self._ensure_tables_exist()
    
    def _ensure_tables_exist(self):
        """Ensure comments table exists in database."""
        conn = get_connection(self.db_path)
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS comments (
                    comment_id TEXT PRIMARY KEY,
                    investigation_id TEXT NOT NULL,
                    artifact_id TEXT,
                    author TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT,
                    parent_id TEXT,
                    comment_type TEXT DEFAULT 'general',
                    FOREIGN KEY (investigation_id) REFERENCES investigations(investigation_id),
                    FOREIGN KEY (artifact_id) REFERENCES artifacts(artifact_id),
                    FOREIGN KEY (parent_id) REFERENCES comments(comment_id)
                )
            """)
            conn.commit()
            logger.debug("Comments table verified")
        finally:
            conn.close()
    
    def add_comment(
        self,
        investigation_id: str,
        content: str,
        author: str = "system",
        artifact_id: Optional[str] = None,
        parent_id: Optional[str] = None,
        comment_type: str = "general"
    ) -> str:
        """
        Add a comment to an investigation or artifact.
        
        Args:
            investigation_id: ID of the investigation
            content: Comment content
            author: Comment author
            artifact_id: Optional artifact ID to comment on
            parent_id: Optional parent comment ID for threading
            comment_type: Type of comment (general, annotation, question, etc.)
            
        Returns:
            Comment ID
        """
        import uuid
        conn = get_connection(self.db_path)
        try:
            comment_id = str(uuid.uuid4())
            created_at = datetime.now().isoformat()
            
            conn.execute("""
                INSERT INTO comments (comment_id, investigation_id, artifact_id, author, content, created_at, parent_id, comment_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (comment_id, investigation_id, artifact_id, author, content, created_at, parent_id, comment_type))
            
            conn.commit()
            logger.info(f"Added comment {comment_id} to investigation {investigation_id}")
            return comment_id
            
        finally:
            conn.close()
    
    def get_investigation_comments(self, investigation_id: str) -> List[Comment]:
        """
        Get all comments for an investigation.
        
        Args:
            investigation_id: ID of the investigation
            
        Returns:
            List of Comment objects
        """
        conn = get_connection(self.db_path)
        try:
            cursor = conn.execute("""
                SELECT comment_id, investigation_id, artifact_id, author, content, created_at, updated_at, parent_id, comment_type
                FROM comments
                WHERE investigation_id = ?
                ORDER BY created_at ASC
            """, (investigation_id,))
            
            comments = []
            for row in cursor.fetchall():
                comments.append(Comment(
                    comment_id=row[0],
                    investigation_id=row[1],
                    artifact_id=row[2],
                    author=row[3],
                    content=row[4],
                    created_at=row[5],
                    updated_at=row[6],
                    parent_id=row[7],
                    comment_type=row[8]
                ))
            
            return comments
            
        finally:
            conn.close()
    
    def get_artifact_comments(self, artifact_id: str) -> List[Comment]:
        """
        Get all comments for a specific artifact.
        
        Args:
            artifact_id: ID of the artifact
            
        Returns:
            List of Comment objects
        """
        conn = get_connection(self.db_path)
        try:
            cursor = conn.execute("""
                SELECT comment_id, investigation_id, artifact_id, author, content, created_at, updated_at, parent_id, comment_type
                FROM comments
                WHERE artifact_id = ?
                ORDER BY created_at ASC
            """, (artifact_id,))
            
            comments = []
            for row in cursor.fetchall():
                comments.append(Comment(
                    comment_id=row[0],
                    investigation_id=row[1],
                    artifact_id=row[2],
                    author=row[3],
                    content=row[4],
                    created_at=row[5],
                    updated_at=row[6],
                    parent_id=row[7],
                    comment_type=row[8]
                ))
            
            return comments
            
        finally:
            conn.close()
    
    def update_comment(self, comment_id: str, content: str, author: str) -> bool:
        """
        Update an existing comment.
        
        Args:
            comment_id: ID of the comment to update
            content: New comment content
            author: Author making the update
            
        Returns:
            True if successful, False otherwise
        """
        conn = get_connection(self.db_path)
        try:
            updated_at = datetime.now().isoformat()
            
            cursor = conn.execute("""
                UPDATE comments
                SET content = ?, updated_at = ?
                WHERE comment_id = ?
            """, (content, updated_at, comment_id))
            
            conn.commit()
            success = cursor.rowcount > 0
            
            if success:
                logger.info(f"Updated comment {comment_id}")
            
            return success
            
        finally:
            conn.close()
    
    def delete_comment(self, comment_id: str) -> bool:
        """
        Delete a comment.
        
        Args:
            comment_id: ID of the comment to delete
            
        Returns:
            True if successful, False otherwise
        """
        conn = get_connection(self.db_path)
        try:
            cursor = conn.execute("""
                DELETE FROM comments
                WHERE comment_id = ?
            """, (comment_id,))
            
            conn.commit()
            success = cursor.rowcount > 0
            
            if success:
                logger.info(f"Deleted comment {comment_id}")
            
            return success
            
        finally:
            conn.close()
    
    def get_comment_thread(self, comment_id: str) -> List[Comment]:
        """
        Get a comment thread (replies to a comment).
        
        Args:
            comment_id: ID of the parent comment
            
        Returns:
            List of Comment objects (replies)
        """
        conn = get_connection(self.db_path)
        try:
            cursor = conn.execute("""
                SELECT comment_id, investigation_id, artifact_id, author, content, created_at, updated_at, parent_id, comment_type
                FROM comments
                WHERE parent_id = ?
                ORDER BY created_at ASC
            """, (comment_id,))
            
            comments = []
            for row in cursor.fetchall():
                comments.append(Comment(
                    comment_id=row[0],
                    investigation_id=row[1],
                    artifact_id=row[2],
                    author=row[3],
                    content=row[4],
                    created_at=row[5],
                    updated_at=row[6],
                    parent_id=row[7],
                    comment_type=row[8]
                ))
            
            return comments
            
        finally:
            conn.close()
    
    def get_comment_count(self, investigation_id: str) -> int:
        """
        Get the total number of comments for an investigation.
        
        Args:
            investigation_id: ID of the investigation
            
        Returns:
            Number of comments
        """
        conn = get_connection(self.db_path)
        try:
            cursor = conn.execute("""
                SELECT COUNT(*)
                FROM comments
                WHERE investigation_id = ?
            """, (investigation_id,))
            
            return cursor.fetchone()[0]
            
        finally:
            conn.close()
