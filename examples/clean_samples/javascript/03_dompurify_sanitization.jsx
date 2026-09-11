import React from 'react';
import DOMPurify from 'dompurify';

export function CommentDisplay({ comment }) {
    const clean = DOMPurify.sanitize(comment.body);
    return (
        <div className="comment">
            <div dangerouslySetInnerHTML={{ __html: clean }} />
        </div>
    );
}

export function PlainTextComment({ comment }) {
    return (
        <div className="comment">
            <p>{comment.body}</p>
        </div>
    );
}

export function StrictSanitization({ content }) {
    const clean = DOMPurify.sanitize(content, {
        ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
        ALLOWED_ATTR: ['href'],
    });
    return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}