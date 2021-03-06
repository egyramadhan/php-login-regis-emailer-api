PGDMP         4             	    x         	   emailsend    13.0    13.0     �           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false            �           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false            �           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false            �           1262    16394 	   emailsend    DATABASE     l   CREATE DATABASE emailsend WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE = 'Indonesian_Indonesia.1252';
    DROP DATABASE emailsend;
                postgres    false            �            1259    16429    posting    TABLE     �   CREATE TABLE public.posting (
    id bigint NOT NULL,
    name_sending character varying(50) NOT NULL,
    email_accept character varying(50) NOT NULL,
    body text NOT NULL
);
    DROP TABLE public.posting;
       public         heap    postgres    false            �            1259    16427    posting_id_seq    SEQUENCE     w   CREATE SEQUENCE public.posting_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 %   DROP SEQUENCE public.posting_id_seq;
       public          postgres    false    203            �           0    0    posting_id_seq    SEQUENCE OWNED BY     A   ALTER SEQUENCE public.posting_id_seq OWNED BY public.posting.id;
          public          postgres    false    202            �            1259    16421    users    TABLE     �   CREATE TABLE public.users (
    id bigint NOT NULL,
    name character varying(50) NOT NULL,
    email character varying(50) NOT NULL,
    password character varying(150) NOT NULL
);
    DROP TABLE public.users;
       public         heap    postgres    false            �            1259    16419    users_id_seq    SEQUENCE     u   CREATE SEQUENCE public.users_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 #   DROP SEQUENCE public.users_id_seq;
       public          postgres    false    201            �           0    0    users_id_seq    SEQUENCE OWNED BY     =   ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;
          public          postgres    false    200            *           2604    16432 
   posting id    DEFAULT     h   ALTER TABLE ONLY public.posting ALTER COLUMN id SET DEFAULT nextval('public.posting_id_seq'::regclass);
 9   ALTER TABLE public.posting ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    203    202    203            )           2604    16424    users id    DEFAULT     d   ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);
 7   ALTER TABLE public.users ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    200    201    201            �          0    16429    posting 
   TABLE DATA           G   COPY public.posting (id, name_sending, email_accept, body) FROM stdin;
    public          postgres    false    203   �       �          0    16421    users 
   TABLE DATA           :   COPY public.users (id, name, email, password) FROM stdin;
    public          postgres    false    201   �       �           0    0    posting_id_seq    SEQUENCE SET     <   SELECT pg_catalog.setval('public.posting_id_seq', 1, true);
          public          postgres    false    202            �           0    0    users_id_seq    SEQUENCE SET     :   SELECT pg_catalog.setval('public.users_id_seq', 2, true);
          public          postgres    false    200            .           2606    16437    posting posting_pkey 
   CONSTRAINT     R   ALTER TABLE ONLY public.posting
    ADD CONSTRAINT posting_pkey PRIMARY KEY (id);
 >   ALTER TABLE ONLY public.posting DROP CONSTRAINT posting_pkey;
       public            postgres    false    203            ,           2606    16426    users users_pkey 
   CONSTRAINT     N   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);
 :   ALTER TABLE ONLY public.users DROP CONSTRAINT users_pkey;
       public            postgres    false    201            �   �   x�M�ANAD�NQ�&�������MwOC'z{��(xU<ݾ%f�xy|=���[����������[b�����Vڀk�L[�.[$l�X��nZH�X��٪��gڜU�)8'ɠ��1BWUA�����T����ybilZ�"(C~z�-�pa��P�;��N��d��$�V2�Ȼ�JW�$��U}X>�eY� DYd{      �   �   x�e��B@ ����p���q�
�"i��s�]F����{�OD�ӆ���F�����}E��H�S�I'
ܡB��K�?RX4o�nIJ�On�������ĔU�<IX�Z	�y���ň�b��T��mǱ��:��'Y"�'=�2b���򪑝�!r��w�"v����0I��`���;O     