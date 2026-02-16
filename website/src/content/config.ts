import { defineCollection, z } from 'astro:content';

const blogCollection = defineCollection({
    type: 'content', // v2.5.0+ content collections
    schema: z.object({
        title: z.string(),
        description: z.string(),
        pubDate: z.date(),
        author: z.string().default('xSend Team'),
        tags: z.array(z.string()).optional(),
    }),
});

const faqCollection = defineCollection({
    type: 'data',
    schema: z.object({
        questions: z.array(z.object({
            q: z.string(),
            a: z.string(),
        })),
    }),
});

export const collections = {
    'blog': blogCollection,
    'faq': faqCollection,
};
