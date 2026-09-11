import React from 'react';

export function CommentDisplay({ comment }) {
    return (
        <div className="comment">
            <div dangerouslySetInnerHTML={{ __html: comment.body }} />
        </div>
    );
}

export function ProfileBio({ user }) {
    const html = `<p><strong>${user.name}</strong>: ${user.bio}</p>`;
    return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

export function SearchResults({ query, results }) {
    return (
        <div>
            <h2>Results for "{query}"</h2>
            {results.map((r, i) => (
                <div key={i} dangerouslySetInnerHTML={{ __html: r.snippet }} />
            ))}
        </div>
    );
}